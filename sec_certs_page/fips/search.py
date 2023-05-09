import operator
import time
from functools import reduce
from typing import Iterable, Mapping, Optional, Tuple, Union

import pymongo
import sentry_sdk
from flask import Request, current_app
from werkzeug.datastructures import MultiDict
from werkzeug.exceptions import BadRequest
from whoosh import highlight, query
from whoosh.qparser import QueryParser
from whoosh.searching import Results, ResultsPage

from .. import get_searcher, mongo
from ..common.objformats import load
from ..common.search.index import index_schema
from ..common.search.query import BasicSearch
from ..common.views import Pagination, entry_file_path
from ..fips import fips_types


class FIPSBasicSearch(BasicSearch):
    status_options = {"Any", "Active", "Historical", "Revoked"}
    status_default = "Any"
    sort_options = {"match", "number", "first_cert_date", "last_cert_date", "sunset_date", "level", "vendor"}
    sort_default = "match"
    categories = fips_types
    collection = mongo.db.fips

    @classmethod
    def select_certs(cls, q, cat, categories, status, sort, **kwargs):
        query = {}
        projection = {
            "_id": 1,
            "cert_id": 1,
            "web_data.module_name": 1,
            "web_data.status": 1,
            "web_data.level": 1,
            "web_data.vendor": 1,
            "web_data.module_type": 1,
            "web_data.validation_history": 1,
            "web_data.date_sunset": 1,
        }

        if q is not None and q != "":
            projection["score"] = {"$meta": "textScore"}
            try:
                iq = int(q)
                query["$or"] = [{"$text": {"$search": q}}, {"cert_id": iq}]
            except ValueError:
                query["$text"] = {"$search": q}

        if cat is not None:
            selected_cats = []
            for name, category in categories.items():
                if category["selected"]:
                    selected_cats.append(name)
            query["web_data.module_type"] = {"$in": selected_cats}
        else:
            for category in categories.values():
                category["selected"] = True

        if status is not None and status != "Any":
            query["web_data.status"] = status

        with sentry_sdk.start_span(op="mongo", description="Find certs."):
            cursor = mongo.db.fips.find(query, projection)
            count = mongo.db.fips.count_documents(query)

        if sort == "match" and q is not None and q != "":
            cursor.sort(
                [
                    ("score", {"$meta": "textScore"}),
                    ("web_data.module_name", pymongo.ASCENDING),
                ]
            )
        elif sort == "number":
            cursor.sort([("cert_id", pymongo.ASCENDING)])
        elif sort == "first_cert_date":
            cursor.sort([("web_data.validation_history.0.date._value", pymongo.ASCENDING)])
        elif sort == "last_cert_date":
            cursor.sort([("web_data.validation_history", pymongo.ASCENDING)])
        elif sort == "sunset_date":
            cursor.sort([("web_data.date_sunset", pymongo.ASCENDING)])
        elif sort == "level":
            cursor.sort([("web_data.level", pymongo.ASCENDING)])
        elif sort == "vendor":
            cursor.sort([("web_data.vendor", pymongo.ASCENDING)])
        else:
            cursor.sort([("cert_id", pymongo.ASCENDING)])
        return cursor, count


class FulltextSearch:
    @classmethod
    def parse_args(cls, args: Union[dict, MultiDict]) -> dict[str, Optional[Union[int, str]]]:
        categories = fips_types.copy()
        try:
            page = int(args.get("page", 1))
        except ValueError:
            raise BadRequest(description="Invalid page number.")
        q = args.get("q", None)
        cat = args.get("cat", None)

        if cat is not None:
            for name, category in categories.items():
                if category["id"] in cat:
                    category["selected"] = True
                else:
                    category["selected"] = False
        else:
            for category in categories.values():
                category["selected"] = True

        document_type = args.get("type", "any")
        if document_type not in ("any", "report", "target"):
            raise BadRequest(description="Invalid type.")

        status = args.get("status", "Any")
        if status not in ("Any", "Active", "Historical", "Revoked"):
            raise BadRequest(description="Invalid status.")

        res = {
            "q": q,
            "page": page,
            "cat": cat,
            "categories": categories,
            "status": status,
            "document_type": document_type,
        }
        return res

    @classmethod
    def select_items(
        cls, q, cat, categories, status, document_type, page=None
    ) -> Tuple[Union[Results, ResultsPage], int]:
        q_filter = query.Term("cert_schema", "fips")
        cat_terms = []
        for name, category in categories.items():
            if category["selected"]:
                cat_terms.append(query.Term("category", category["id"]))
        q_filter &= reduce(operator.or_, cat_terms)
        if document_type != "any":
            q_filter &= query.Term("document_type", document_type)
        if status != "Any":
            q_filter &= query.Term("status", status)

        per_page = current_app.config["SEARCH_ITEMS_PER_PAGE"]

        parser = QueryParser("content", schema=index_schema)
        qr = parser.parse(q)
        with sentry_sdk.start_span(op="whoosh.get_searcher", description="Get whoosh searcher"):
            searcher = get_searcher()
        with sentry_sdk.start_span(op="whoosh.search", description="Search"):
            if page is None:
                res = searcher.search(qr, filter=q_filter, limit=None, scored=False)
            else:
                res = searcher.search_page(qr, pagenum=page, filter=q_filter, pagelen=per_page)
        return res, len(res)

    @classmethod
    def select_certs(cls, q, cat, categories, status, document_type, **kwargs) -> Tuple[Iterable[Mapping], int]:
        res, count = cls.select_items(q, cat, categories, status, document_type, **kwargs)
        dgsts = set(map(operator.itemgetter("dgst"), res))
        certs = list(map(lambda dgst: load(mongo.db.fips.find_one({"_id": dgst})), dgsts))
        return certs, len(certs)

    @classmethod
    def process_search(cls, req: Request):
        parsed = cls.parse_args(req.args)
        if parsed["q"] is None:
            return {"pagination": None, "results": [], **parsed}
        res, count = cls.select_items(**parsed)

        page = parsed["page"]

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
                cert = mongo.db.fips.find_one({"_id": dgst})
                entry = {"hit": hit, "cert": cert}
                fpath = entry_file_path(dgst, current_app.config["DATASET_PATH_FIPS_DIR"], hit["document_type"], "txt")
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
            total=mongo.db.fips.count_documents({}),
            css_framework="bootstrap5",
            alignment="center",
        )
        return {
            "pagination": pagination,
            "results": results,
            "runtime": runtime,
            "highlight_runtime": highlite_runtime,
            **parsed,
        }
