from typing import Optional, Union

import pymongo
import sentry_sdk
from flask import current_app
from werkzeug.datastructures import MultiDict
from werkzeug.exceptions import BadRequest

from sec_certs_page import mongo
from sec_certs_page.common.objformats import load
from sec_certs_page.common.views import Pagination
from sec_certs_page.fips import fips_types


class BasicSearch:
    @classmethod
    def parse_args(cls, args: Union[dict, MultiDict]) -> dict[str, Optional[Union[int, str]]]:
        """Parse the request into validated args."""
        try:
            page = int(args.get("page", 1))
        except ValueError:
            raise BadRequest(description="Invalid page number.")
        q = args.get("q", None)
        cat = args.get("cat", None)
        status = args.get("status", "Any")
        if status not in ("Any", "Active", "Historical", "Revoked"):
            raise BadRequest(description="Invalid status.")
        sort = args.get("sort", "match")
        if sort not in ("match", "number", "first_cert_date", "last_cert_date", "sunset_date", "level", "vendor"):
            raise BadRequest(description="Invalid sort.")
        res = {"q": q, "page": page, "cat": cat, "status": status, "sort": sort}
        return res

    @classmethod
    def select_certs(cls, q, cat, status, sort, **kwargs):
        categories = fips_types.copy()
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
                if category["id"] in cat:
                    selected_cats.append(name)
                    category["selected"] = True
                else:
                    category["selected"] = False
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
        return cursor, categories, count

    @classmethod
    def process_search(cls, req, callback=None):
        parsed = cls.parse_args(req.args)
        cursor, categories, count = cls.select_certs(**parsed)

        page = parsed["page"]

        per_page = current_app.config["SEARCH_ITEMS_PER_PAGE"]
        pagination = Pagination(
            page=page,
            per_page=per_page,
            search=True,
            found=count,
            total=mongo.db.fips.count_documents({}),
            css_framework="bootstrap5",
            alignment="center",
            url_callback=callback,
        )
        return {
            "pagination": pagination,
            "certs": list(map(load, cursor[(page - 1) * per_page : page * per_page])),
            "categories": categories,
            **parsed,
        }
