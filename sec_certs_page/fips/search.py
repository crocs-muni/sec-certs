from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Tuple

import pymongo
import sentry_sdk
from pymongo.cursor import Cursor

from .. import mongo
from ..common.search.query import BasicSearch, FulltextSearch
from ..fips import fips_types


class FIPSBasicSearch(BasicSearch):
    status_options = {"Any", "Active", "Historical", "Revoked"}
    status_default = "Any"
    sort_options = {"match", "number", "first_cert_date", "last_cert_date", "sunset_date", "level", "vendor"}
    sort_default = "match"
    categories = fips_types  # type: ignore
    collection = mongo.db.fips

    @classmethod
    def select_certs(
        cls, q, cat, categories, status, sort, **kwargs
    ) -> Tuple[Cursor[Mapping], int, List[Optional[datetime]]]:
        query: Dict[str, Any] = {}
        projection: Dict[str, Any] = {
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
            cursor: Cursor[Mapping] = cls.collection.find(query, projection)
            count: int = cls.collection.count_documents(query)

        timeline: List[Optional[datetime]] = []
        for cert in cursor.clone():
            val_history = cert["web_data"]["validation_history"]
            if not val_history:
                continue
            zero = val_history[0]
            if not zero:
                continue
            val = zero["date"]["_value"]
            if not val:
                continue
            timeline.append(datetime.strptime(val, "%Y-%m-%d"))

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
        return cursor, count, timeline


class FIPSFulltextSearch(FulltextSearch):
    schema = "fips"
    status_options = {"Any", "Active", "Historical", "Revoked"}
    status_default = "Any"
    type_options = {"any", "report", "target"}
    type_default = "any"
    categories = fips_types  # type: ignore
    collection = mongo.db.fips
    doc_dir = "DATASET_PATH_FIPS_DIR"
