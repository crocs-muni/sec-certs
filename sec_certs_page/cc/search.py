import operator
import time
from functools import reduce
from typing import Iterable, Mapping, Optional, Tuple, Union

import pymongo
import sentry_sdk
from flask import Request, current_app
from werkzeug.exceptions import BadRequest
from whoosh import highlight
from whoosh.qparser import QueryParser, query
from whoosh.searching import ResultsPage

from .. import mongo
from ..cc import cc_categories, get_cc_searcher
from ..common.objformats import load
from ..common.search import index_schema
from ..common.views import Pagination, entry_file_path


class BasicSearch:
    @classmethod
    def parse_req(cls, req: Request) -> Mapping[str, Optional[Union[int, str]]]:
        """Parse the request into validated args."""
        try:
            page = int(req.args.get("page", 1))
        except ValueError:
            raise BadRequest(description="Invalid page number.")
        q = req.args.get("q", None)
        cat = req.args.get("cat", None)
        categories = cc_categories.copy()
        if cat is not None:
            for name, category in categories.items():
                if category["id"] in cat:
                    category["selected"] = True
                else:
                    category["selected"] = False
        else:
            for category in categories.values():
                category["selected"] = True
        status = req.args.get("status", "any")
        if status not in ("any", "active", "archived"):
            raise BadRequest(description="Invalid status.")
        sort = req.args.get("sort", "match")
        if sort not in ("match", "name", "cert_date", "archive_date"):
            raise BadRequest(description="Invalid sort.")
        return {"q": q, "page": page, "cat": cat, "categories": categories, "sort": sort, "status": status}

    @classmethod
    def select_certs(cls, q, cat, categories, status, sort, page) -> Tuple[Iterable[Mapping], int]:
        """Take parsed args and get the certs as: cursor and count."""
        query = {}
        projection = {
            "_id": 1,
            "name": 1,
            "status": 1,
            "not_valid_before": 1,
            "not_valid_after": 1,
            "category": 1,
            "heuristics.cert_id": 1,
        }

        if q is not None and q != "":
            projection["score"] = {"$meta": "textScore"}  # type: ignore
            query["$text"] = {"$search": q}

        if cat is not None:
            selected_cats = []
            for name, category in categories.items():
                if category["selected"]:
                    selected_cats.append(name)
            query["category"] = {"$in": selected_cats}

        if status is not None and status != "any":
            query["status"] = status

        with sentry_sdk.start_span(op="mongo", description="Find certs."):
            cursor = mongo.db.cc.find(query, projection)
            count = mongo.db.cc.count_documents(query)

        if sort == "match" and q is not None and q != "":
            cursor.sort([("score", {"$meta": "textScore"}), ("name", pymongo.ASCENDING)])
        elif sort == "cert_date":
            cursor.sort([("not_valid_before._value", pymongo.ASCENDING)])
        elif sort == "archive_date":
            cursor.sort([("not_valid_after._value", pymongo.ASCENDING)])
        else:
            cursor.sort([("name", pymongo.ASCENDING)])

        return cursor, count

    @classmethod
    def process_search(cls, req, callback=None):
        args = cls.parse_req(req)
        cursor, count = cls.select_certs(**args)

        page = args["page"]

        per_page = current_app.config["SEARCH_ITEMS_PER_PAGE"]
        pagination = Pagination(
            page=page,
            per_page=per_page,
            search=True,
            found=count,
            total=mongo.db.cc.count_documents({}),
            css_framework="bootstrap5",
            alignment="center",
            url_callback=callback,
        )
        return {
            "pagination": pagination,
            "certs": list(map(load, cursor[(page - 1) * per_page : page * per_page])),
            **args,
        }


class FulltextSearch:
    @classmethod
    def parse_req(cls, req):
        categories = cc_categories.copy()
        try:
            page = int(req.args.get("page", 1))
        except ValueError:
            raise BadRequest(description="Invalid page number.")
        q = req.args.get("q", None)
        cat = req.args.get("cat", None)
        if cat is not None:
            for name, category in categories.items():
                if category["id"] in cat:
                    category["selected"] = True
                else:
                    category["selected"] = False
        else:
            for category in categories.values():
                category["selected"] = True

        document_type = req.args.get("type", "any")
        if document_type not in ("any", "report", "target"):
            raise BadRequest(description="Invalid type.")

        status = req.args.get("status", "any")
        if status not in ("any", "active", "archived"):
            raise BadRequest(description="Invalid status.")
        return {
            "q": q,
            "page": page,
            "cat": cat,
            "categories": categories,
            "status": status,
            "document_type": document_type,
        }

    @classmethod
    def select_items(cls, q, cat, categories, status, document_type, page) -> Tuple[ResultsPage, int]:
        q_filter = query.Term("cert_schema", "cc")
        cat_terms = []
        for name, category in categories.items():
            if category["selected"]:
                cat_terms.append(query.Term("category", category["id"]))
        q_filter &= reduce(operator.or_, cat_terms)
        if document_type != "any":
            q_filter &= query.Term("document_type", document_type)
        if status != "any":
            q_filter &= query.Term("status", status)

        per_page = current_app.config["SEARCH_ITEMS_PER_PAGE"]

        parser = QueryParser("content", schema=index_schema)
        qr = parser.parse(q)
        print(q)
        print(qr)
        with sentry_sdk.start_span(op="whoosh.get_searcher", description="Get whoosh searcher"):
            searcher = get_cc_searcher()
        with sentry_sdk.start_span(op="whoosh.search", description=f"Search {qr}"):
            res = searcher.search_page(qr, pagenum=page, filter=q_filter, pagelen=per_page)
        return res, len(res)

    @classmethod
    def select_certs(cls, q, cat, categories, status, document_type, page) -> Tuple[Iterable[Mapping], int]:
        res, count = cls.select_items(q, cat, categories, status, document_type, page)
        dgsts = set(map(operator.itemgetter("dgst"), res))
        return list(map(lambda dgst: load(mongo.db.cc.find_one({"_id": dgst})), dgsts)), count

    @classmethod
    def process_search(cls, req):
        args = cls.parse_req(req)
        if args["q"] is None:
            return {"pagination": None, "results": [], **args}
        res, count = cls.select_items(**args)

        page = args["page"]

        per_page = current_app.config["SEARCH_ITEMS_PER_PAGE"]

        res.results.fragmenter.charlimit = None
        res.results.fragmenter.maxchars = 300
        res.results.fragmenter.surround = 40
        res.results.order = highlight.SCORE
        hf = highlight.HtmlFormatter(between="<br/>")
        res.results.formatter = hf
        runtime = res.results.runtime
        results = []
        highlite_start = time.perf_counter()
        with sentry_sdk.start_span(op="whoosh.highlight", description="Highlight results"):
            for hit in res:
                dgst = hit["dgst"]
                cert = mongo.db.cc.find_one({"_id": dgst})
                entry = {"hit": hit, "cert": cert}
                fpath = entry_file_path(dgst, current_app.config["DATASET_PATH_CC_DIR"], hit["document_type"], "txt")
                try:
                    with open(fpath) as f:
                        contents = f.read()
                    hlt = hit.highlights("content", text=contents)
                    entry["highlights"] = hlt
                except FileNotFoundError:
                    pass
                results.append(entry)
        highlite_runtime = time.perf_counter() - highlite_start

        pagination = Pagination(
            page=page,
            per_page=per_page,
            search=True,
            found=count,
            total=mongo.db.cc.count_documents({}),
            css_framework="bootstrap5",
            alignment="center",
        )
        return {
            "pagination": pagination,
            "results": results,
            "runtime": runtime,
            "highlight_runtime": highlite_runtime,
            **args,
        }
