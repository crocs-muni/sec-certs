from datetime import datetime
from typing import List, Mapping, Optional, Sequence, Tuple, Union

import pymongo
import sentry_sdk
from werkzeug.datastructures import MultiDict

from .. import mongo
from ..cc import cc_categories
from ..common.search.query import BasicSearch, FulltextSearch


class PPBasicSearch(BasicSearch):
    status_options = {"any", "active", "archived"}
    status_default = "any"
    sort_options = {"match", "name", "cert_date", "archive_date"}
    sort_default = "match"
    categories = cc_categories  # type: ignore
    collection = mongo.db.pp

    @classmethod
    def parse_args(cls, args: Union[dict, MultiDict]) -> dict[str, Optional[Union[int, str]]]:
        res = super().parse_args(args)
        scheme = args.get("scheme", "any")
        res["scheme"] = scheme
        if scheme != "any":
            res["advanced"] = True
        return res

    @classmethod
    def select_certs(cls, q, cat, categories, status, sort, **kwargs) -> Tuple[Sequence[Mapping], int, List[datetime]]:
        """Take parsed args and get the certs as: cursor and count."""
        query = {}
        projection = {
            "_id": 1,
            "web_data.name": 1,
            "web_data.status": 1,
            "web_data.scheme": 1,
            "web_data.security_level._value": 1,
            "web_data.not_valid_before": 1,
            "web_data.not_valid_after": 1,
            "web_data.category": 1,
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

        with sentry_sdk.start_span(op="mongo", description="Find certs."):
            cursor = PPBasicSearch.collection.find(query, projection)
            count = PPBasicSearch.collection.count_documents(query)

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

    @classmethod
    def parse_args(cls, args: Union[dict, MultiDict]) -> dict[str, Optional[Union[int, str]]]:
        res = super().parse_args(args)
        scheme = args.get("scheme", "any")
        res["scheme"] = scheme
        if scheme != "any":
            res["advanced"] = True
        return res
