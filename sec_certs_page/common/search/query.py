import operator
import time
from abc import ABC, abstractmethod
from functools import reduce
from typing import ClassVar, Iterable, Mapping, Optional, Set, Tuple, Union

import sentry_sdk
from flask import Request, current_app
from werkzeug.datastructures import MultiDict
from werkzeug.exceptions import BadRequest
from whoosh import highlight, query
from whoosh.qparser import QueryParser
from whoosh.searching import Results, ResultsPage

from ... import get_searcher
from ..objformats import load
from ..views import Pagination, entry_file_path
from .index import index_schema


class BasicSearch(ABC):
    status_options: ClassVar[Set[str]]
    status_default: ClassVar[str]
    sort_options: ClassVar[Set[str]]
    sort_default: ClassVar[str]
    categories: ClassVar[dict[str, dict]]
    collection: ClassVar

    @classmethod
    def parse_args(cls, args: Union[dict, MultiDict]) -> dict[str, Optional[Union[int, str]]]:
        """Parse the request into validated args."""
        try:
            page = int(args.get("page", 1))
        except ValueError:
            raise BadRequest(description="Invalid page number.")
        q = args.get("q", None)
        cat = args.get("cat", None)
        advanced = False
        categories = cls.categories.copy()
        if cat is not None:
            for name, category in categories.items():
                category["selected"] = category["id"] in cat
                if category["id"] not in cat:
                    advanced = True
        else:
            for category in categories.values():
                category["selected"] = True
        status = args.get("status", cls.status_default)
        if status not in cls.status_options:
            raise BadRequest(description="Invalid status.")
        if status != cls.status_default:
            advanced = True
        sort = args.get("sort", cls.sort_default)
        if sort not in cls.sort_options:
            raise BadRequest(description="Invalid sort.")
        if sort != cls.sort_default:
            advanced = True
        res = {
            "q": q,
            "page": page,
            "cat": cat,
            "categories": categories,
            "sort": sort,
            "status": status,
            "advanced": advanced,
        }
        return res

    @classmethod
    @abstractmethod
    def select_certs(cls, q, cat, categories, status, sort, **kwargs):
        raise NotImplementedError

    @classmethod
    def process_search(cls, req, callback=None):
        parsed = cls.parse_args(req.args)
        cursor, count, timeline = cls.select_certs(**parsed)

        page = parsed["page"]

        per_page = current_app.config["SEARCH_ITEMS_PER_PAGE"]
        pagination = Pagination(
            page=page,
            per_page=per_page,
            search=True,
            found=count,
            total=cls.collection.count_documents({}),
            css_framework="bootstrap5",
            alignment="center",
            url_callback=callback,
            next_rel="next",
            prev_rel="prev",
        )
        return {
            "pagination": pagination,
            "certs": list(map(load, cursor[(page - 1) * per_page : page * per_page])),
            "timeline": timeline,
            **parsed,
        }


class FulltextSearch(ABC):
    schema: ClassVar[str]
    status_options: ClassVar[Set[str]]
    status_default: ClassVar[str]
    type_options: ClassVar[Set[str]]
    type_default: ClassVar[str]
    categories: ClassVar[dict[str, dict]]
    collection: ClassVar
    doc_dir: ClassVar[str]

    @classmethod
    def parse_args(cls, args: Union[dict, MultiDict]) -> dict[str, Optional[Union[int, str]]]:
        categories = cls.categories.copy()
        try:
            page = int(args.get("page", 1))
        except ValueError:
            raise BadRequest(description="Invalid page number.")
        if page < 1:
            raise BadRequest(description="Invalid page number, must be >= 1.")
        q = args.get("q", None)
        cat = args.get("cat", None)
        advanced = False
        if cat is not None:
            for name, category in categories.items():
                category["selected"] = category["id"] in cat
                if category["id"] not in cat:
                    advanced = True
        else:
            for category in categories.values():
                category["selected"] = True

        document_type = args.get("type", cls.type_default)
        if document_type not in cls.type_options:
            raise BadRequest(description="Invalid type.")
        if document_type != cls.type_default:
            advanced = True

        status = args.get("status", cls.status_default)
        if status not in cls.status_options:
            raise BadRequest(description="Invalid status.")
        if status != cls.status_default:
            advanced = True
        res = {
            "q": q,
            "page": page,
            "cat": cat,
            "categories": categories,
            "status": status,
            "document_type": document_type,
            "advanced": advanced,
        }
        return res

    @classmethod
    def select_items(
        cls, q, cat, categories, status, document_type, page=None, **kwargs
    ) -> Tuple[Union[Results, ResultsPage], int]:
        q_filter = query.Term("cert_schema", cls.schema)
        cat_terms = []
        for name, category in categories.items():
            if category["selected"]:
                cat_terms.append(query.Term("category", category["id"]))
        q_filter &= reduce(operator.or_, cat_terms)
        if document_type != "any":
            q_filter &= query.Term("document_type", document_type)
        if status.lower() != "any":
            q_filter &= query.Term("status", status)
        if "scheme" in kwargs and kwargs["scheme"] != "any":
            q_filter &= query.Term("scheme", kwargs["scheme"])

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
        certs = list(map(lambda dgst: load(cls.collection.find_one({"_id": dgst})), dgsts))
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
                cert = cls.collection.find_one({"_id": dgst})
                entry = {"hit": hit, "cert": cert}
                fpath = entry_file_path(dgst, current_app.config[cls.doc_dir], hit["document_type"], "txt")
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
            total=cls.collection.count_documents({}),
            css_framework="bootstrap5",
            alignment="center",
            next_rel="next",
            prev_rel="prev",
        )
        return {
            "pagination": pagination,
            "results": results,
            "runtime": runtime,
            "highlight_runtime": highlite_runtime,
            **parsed,
        }
