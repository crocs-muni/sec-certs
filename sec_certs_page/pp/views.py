import random
import re
from operator import itemgetter
from pathlib import Path

import pymongo
import sentry_sdk
from flask import render_template, abort, url_for, request, current_app, redirect, send_file
from flask_breadcrumbs import register_breadcrumb

from . import pp
from .. import mongo
from ..cc import cc_categories
from ..utils import add_dots, Pagination, send_json_attachment


@pp.route("/")
@register_breadcrumb(pp, ".", "Protection Profiles")
def index():
    return render_template("pp/index.html.jinja2", title="Protection Profiles | seccerts.org")


@pp.route("/network/")
@register_breadcrumb(pp, ".network", "References")
def network():
    return render_template("pp/network.html.jinja2")


@pp.route("/dataset.json")
def dataset():
    return send_file(Path(current_app.instance_path) / "pp.json", as_attachment=True,
                     mimetype="application/json", attachment_filename="dataset.json")


def select_certs(q, cat, status, sort):
    categories = cc_categories.copy()
    query = {}
    projection = {
        "_id": 1,
        "csv_scan.cc_pp_name": 1,
        "csv_scan.cert_status": 1,
        "csv_scan.cc_certification_date": 1,
        "csv_scan.cc_archived_date": 1,
        "csv_scan.cc_category": 1,
        "processed.cc_pp_csvid": 1
    }

    if q is not None and q != "":
        projection["score"] = {"$meta": "textScore"}
        re_q = ".*" + re.escape(q) + ".*"
        query["$or"] = [{"$text": {"$search": q}}, {"csv_scan.cc_pp_name": {"$regex": re_q, "$options": "i"}}]

    if cat is not None:
        selected_cats = []
        for name, category in categories.items():
            if category["id"] in cat:
                selected_cats.append(name)
                category["selected"] = True
            else:
                category["selected"] = False
        query["csv_scan.cc_category"] = {"$in": selected_cats}
    else:
        for category in categories.values():
            category["selected"] = True

    if status is not None and status != "any":
        query["csv_scan.cert_status"] = status

    cursor = mongo.db.pp.find(query, projection)

    if sort == "match" and q is not None and q != "":
        cursor.sort([("score", {"$meta": "textScore"}), ("csv_scan.cc_pp_name", pymongo.ASCENDING)])
    elif sort == "cert_date":
        cursor.sort([("csv_scan.cc_certification_date", pymongo.ASCENDING)])
    elif sort == "archive_date":
        cursor.sort([("csv_scan.cc_archived_date", pymongo.ASCENDING)])
    else:
        cursor.sort([("csv_scan.cc_pp_name", pymongo.ASCENDING)])

    return cursor, categories


def process_search(req, callback=None):
    page = int(req.args.get("page", 1))
    q = req.args.get("q", None)
    cat = req.args.get("cat", None)
    status = req.args.get("status", "any")
    sort = req.args.get("sort", "match")

    cursor, categories = select_certs(q, cat, status, sort)

    per_page = current_app.config["SEARCH_ITEMS_PER_PAGE"]
    pagination = Pagination(page=page, per_page=per_page, search=True, found=cursor.count(),
                            total=mongo.db.pp.count_documents({}),
                            css_framework="bootstrap4", alignment="center",
                            url_callback=callback)
    return {
        "pagination": pagination,
        "profiles": cursor[(page - 1) * per_page:page * per_page],
        "categories": categories,
        "q": q,
        "page": page,
        "status": status,
        "sort": sort
    }


@pp.route("/search/")
@register_breadcrumb(pp, ".search", "Search")
def search():
    res = process_search(request)
    return render_template("pp/search.html.jinja2", **res,
                           title=f"Protection Profile [{res['q']}] ({res['page']}) | seccerts.org")


@pp.route("/search/pagination/")
def search_pagination():
    def callback(**kwargs):
        return url_for(".search", **kwargs)

    res = process_search(request, callback=callback)
    return render_template("pp/search_pagination.html.jinja2", **res)


@pp.route("/<string(length=20):hashid>/")
@register_breadcrumb(pp, ".entry", "",
                     dynamic_list_constructor=lambda *args, **kwargs: [{"text": request.view_args["hashid"]}])
def entry(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find profile"):
        doc = mongo.db.pp.find_one({"_id": hashid})
    if doc:
        with sentry_sdk.start_span(op="mongo", description="Find certs"):
            certs = []
            if "processed" in doc and "cc_pp_csvid" in doc["processed"]:
                ids = doc["processed"]["cc_pp_csvid"]
                if ids:
                    re_q = ".*" + re.escape(ids[0]) + ".*"
                    docs = mongo.db.cc.find({"$or":
                                                 [{"csv_scan.cc_protection_profiles": {"$regex": re_q,
                                                                                       "$options": "i"}},
                                                  {"processed.cc_pp_id": {"$regex": re_q, "$options": "i"}}]})
                    certs = list(map(add_dots, docs))
        return render_template("pp/entry.html.jinja2", profile=add_dots(doc), hashid=hashid, certs=certs)
    else:
        return abort(404)


@pp.route("/<string(length=20):hashid>/profile.json")
def entry_json(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find profile"):
        doc = mongo.db.pp.find_one({"_id": hashid})
    if doc:
        return send_json_attachment(add_dots(doc))
    else:
        return abort(404)


@pp.route("/analysis/")
@register_breadcrumb(pp, ".analysis", "Analysis")
def analysis():
    return render_template("pp/analysis.html.jinja2")


@pp.route("/random/")
def rand():
    current_ids = list(map(itemgetter("_id"), mongo.db.pp.find({}, ["_id"])))
    return redirect(url_for(".entry", hashid=random.choice(current_ids)))
