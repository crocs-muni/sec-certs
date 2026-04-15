from datetime import datetime
from typing import Any, List, Mapping, Optional, Tuple, Union

import pymongo
import sentry_sdk
from pymongo.cursor import Cursor
from werkzeug.datastructures import MultiDict
from whoosh import query as whoosh_query
from whoosh.searching import Results, ResultsPage

from .. import mongo
from ..cc import cc_categories
from ..common.search.query import BasicSearch, FulltextSearch
from ..common.sentry import metrics


class PPBasicSearch(BasicSearch):
    status_options = {"any", "active", "archived"}
    status_default = "any"
    sort_options = {"match", "name", "cert_date", "archive_date"}
    sort_default = "match"
    categories = cc_categories  # type: ignore
    collection = mongo.db.pp
    source_options = {"any", "cc_portal", "niap", "both"}
    source_default = "any"

    @classmethod
    def parse_args(cls, args: Union[dict, MultiDict]) -> dict[str, Optional[Union[int, str]]]:
        res = super().parse_args(args)
        scheme = args.get("scheme", "any")
        res["scheme"] = scheme
        if scheme != "any":
            res["advanced"] = True
        source = args.get("source", cls.source_default)
        if source not in cls.source_options:
            source = cls.source_default
        res["source"] = source
        if source != cls.source_default:
            res["advanced"] = True
        return res

    @classmethod
    def select_certs(
        cls, q, cat, categories, status, sort, **kwargs
    ) -> Tuple[Cursor[Mapping], int, List[Optional[datetime]]]:
        """Take parsed args and get the certs as: cursor and count."""
        query: dict[str, Any] = {}
        projection = {
            "_id": 1,
            "web_data.name": 1,
            "web_data.status": 1,
            "web_data.scheme": 1,
            "web_data.security_level._value": 1,
            "web_data.not_valid_before": 1,
            "web_data.not_valid_after": 1,
            "web_data.category": 1,
            "web_data.source": 1,
        }

        if q is not None and q != "":
            projection["score"] = {"$meta": "textScore"}  # type: ignore
            query["$text"] = {"$search": q}

        if cat is not None:
            selected_cats = []
            for name, category in categories.items():
                if category["selected"]:
                    selected_cats.append(name)
            query["web_data.category"] = {"$in": selected_cats}

        if status is not None and status != "any":
            query["web_data.status"] = status

        if "scheme" in kwargs and kwargs["scheme"] != "any":
            query["web_data.scheme"] = kwargs["scheme"]

        if "eal" in kwargs and kwargs["eal"] != "any":
            query["web_data.security_level._value"] = kwargs["eal"]

        if "source" in kwargs and kwargs["source"] != "any":
            if kwargs["source"] == "cc_portal":
                source_filter: list[dict] = [
                    {"web_data.source": {"$in": ["cc_portal", "both"]}},
                    {"web_data.source": {"$exists": False}},
                ]
                if "$or" in query:
                    existing_or = query.pop("$or")
                    and_clauses: list[dict] = query.pop("$and", [])
                    and_clauses.append({"$or": existing_or})
                    and_clauses.append({"$or": source_filter})
                    query["$and"] = and_clauses
                else:
                    query["$or"] = source_filter
            elif kwargs["source"] == "niap":
                query["web_data.source"] = {"$in": ["niap", "both"]}
            elif kwargs["source"] == "both":
                query["web_data.source"] = "both"

        with metrics.timing("search.latency", attributes={"collection": "pp", "type": "basic"}):
            with sentry_sdk.start_span(op="mongo", name="Find certs."):
                cursor: Cursor[Mapping] = cls.collection.find(query, projection)
                count: int = cls.collection.count_documents(query)

        metrics.distribution("search.results_count", count, attributes={"collection": "pp"})

        timeline = [
            (
                datetime.strptime(cert["web_data"]["not_valid_before"]["_value"], "%Y-%m-%d")
                if cert["web_data"]["not_valid_before"]
                else None
            )
            for cert in cursor.clone()
        ]

        if sort == "match" and q is not None and q != "":
            cursor.sort([("score", {"$meta": "textScore"}), ("name", pymongo.ASCENDING)])
        elif sort == "cert_date":
            cursor.sort([("web_data.not_valid_before._value", pymongo.ASCENDING)])
        elif sort == "archive_date":
            cursor.sort([("web_data.not_valid_after._value", pymongo.ASCENDING)])
        else:
            cursor.sort([("web_data.name", pymongo.ASCENDING)])

        return cursor, count, timeline


class PPFulltextSearch(FulltextSearch):
    schema = "pp"
    status_options = {"any", "active", "archived"}
    status_default = "any"
    type_options = {"any", "report", "profile"}
    type_default = "any"
    categories = cc_categories  # type: ignore
    collection = mongo.db.pp
    doc_dir = "DATASET_PATH_PP_DIR"
    source_options = {"any", "cc_portal", "niap", "both"}
    source_default = "any"

    @classmethod
    def parse_args(cls, args: Union[dict, MultiDict]) -> dict[str, Optional[Union[int, str]]]:
        res = super().parse_args(args)
        scheme = args.get("scheme", "any")
        res["scheme"] = scheme
        if scheme != "any":
            res["advanced"] = True
        source = args.get("source", cls.source_default)
        if source not in cls.source_options:
            source = cls.source_default
        res["source"] = source
        if source != cls.source_default:
            res["advanced"] = True
        return res

    @classmethod
    def select_items(
        cls, q, cat, categories, status, document_type, page=None, **kwargs
    ) -> Tuple[Union[Results, ResultsPage], int, whoosh_query.Query]:
        source = kwargs.pop("source", cls.source_default)
        res, count, qr = super().select_items(q, cat, categories, status, document_type, page=page, **kwargs)
        if source != "any":
            filtered = []
            for hit in res:
                dgst = hit["dgst"]
                cert = cls.collection.find_one({"_id": dgst}, {"web_data.source": 1})
                if cert:
                    cert_source = cert.get("web_data", {}).get("source")
                    if source == "cc_portal" and cert_source in ("cc_portal", "both", None):
                        filtered.append(hit)
                    elif source == "niap" and cert_source in ("niap", "both"):
                        filtered.append(hit)
                    elif source == "both" and cert_source == "both":
                        filtered.append(hit)
            return filtered, len(filtered), qr  # type: ignore[return-value]
        return res, count, qr
