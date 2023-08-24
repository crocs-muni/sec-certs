from datetime import datetime
from typing import List, Mapping, Sequence, Tuple

import pymongo
import sentry_sdk

from .. import mongo
from ..cc import cc_categories
from ..common.search.query import BasicSearch, FulltextSearch


class CCBasicSearch(BasicSearch):
    status_options = {"any", "active", "archived"}
    status_default = "any"
    sort_options = {"match", "name", "cert_date", "archive_date"}
    sort_default = "match"
    categories = cc_categories  # type: ignore
    collection = mongo.db.cc

    @classmethod
    def select_certs(cls, q, cat, categories, status, sort, **kwargs) -> Tuple[Sequence[Mapping], int, List[datetime]]:
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

        timeline = [datetime.strptime(cert["not_valid_before"]["_value"], "%Y-%m-%d") for cert in cursor.clone()]

        if sort == "match" and q is not None and q != "":
            cursor.sort([("score", {"$meta": "textScore"}), ("name", pymongo.ASCENDING)])
        elif sort == "cert_date":
            cursor.sort([("not_valid_before._value", pymongo.ASCENDING)])
        elif sort == "archive_date":
            cursor.sort([("not_valid_after._value", pymongo.ASCENDING)])
        else:
            cursor.sort([("name", pymongo.ASCENDING)])

        return cursor, count, timeline


class CCFulltextSearch(FulltextSearch):
    schema = "cc"
    status_options = {"any", "active", "archived"}
    status_default = "any"
    type_options = {"any", "report", "target"}
    type_default = "any"
    categories = cc_categories  # type: ignore
    collection = mongo.db.cc
    doc_dir = "DATASET_PATH_CC_DIR"
