import random
import re
from operator import itemgetter
from pathlib import Path

import pymongo
import sentry_sdk
from flask import abort, current_app, redirect, render_template, request, send_file, url_for
from flask_breadcrumbs import register_breadcrumb
from werkzeug.exceptions import BadRequest

from .. import mongo, sitemap
from ..cc import cc_categories
from ..common.objformats import StorageFormat, load
from ..common.views import Pagination, send_json_attachment
from . import pp


@pp.route("/")
@register_breadcrumb(pp, ".", "Protection Profiles")
def index():
    last_ok_run = mongo.db.pp_log.find_one({"ok": True}, sort=[("start_time", pymongo.DESCENDING)])
    return render_template("pp/index.html.jinja2", last_ok_run=last_ok_run)


@pp.route("/network/")
@register_breadcrumb(pp, ".network", "References")
def network():
    return render_template("pp/network.html.jinja2")


@pp.route("/dataset.json")
def dataset():
    """Protection Profile dataset API endpoint."""
    dset_path = Path(current_app.instance_path) / current_app.config["DATASET_PATH_PP_OUT"]
    if not dset_path.is_file():
        return abort(404)
    return send_file(
        dset_path,
        as_attachment=True,
        mimetype="application/json",
        download_name="dataset.json",
    )


@pp.route("/cc.tar.gz")
def dataset_archive():
    """Protection Profile dataset archive API endpoint."""
    archive_path = Path(current_app.instance_path) / current_app.config["DATASET_PATH_PP_ARCHIVE"]
    if not archive_path.is_file():
        return abort(404)
    return send_file(
        archive_path,
        as_attachment=True,
        mimetype="application/gzip",
        download_name="pp.tar.gz",
    )


# TODO: Unify PP search with the rest to enable full text search
def select_certs(q, cat, status, sort):
    categories = cc_categories.copy()
    query = {}
    projection = {
        "_id": 1,
        "web_data.name": 1,
        "web_data.status": 1,
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
            if category["id"] in cat:
                selected_cats.append(name)
                category["selected"] = True
            else:
                category["selected"] = False
        query["web_data.category"] = {"$in": selected_cats}
    else:
        for category in categories.values():
            category["selected"] = True

    if status is not None and status != "any":
        query["web_data.status"] = status

    cursor = mongo.db.pp.find(query, projection)
    count = mongo.db.pp.count_documents(query)

    if sort == "match" and q is not None and q != "":
        cursor.sort(
            [
                ("score", {"$meta": "textScore"}),
                ("web_data.name", pymongo.ASCENDING),
            ]
        )
    elif sort == "cert_date":
        cursor.sort([("web_data.not_valid_before", pymongo.ASCENDING)])
    elif sort == "archive_date":
        cursor.sort([("web_data.not_valid_after", pymongo.ASCENDING)])
    else:
        cursor.sort([("web_data.name", pymongo.ASCENDING)])

    return cursor, categories, count


def process_search(req, callback=None):
    try:
        page = int(req.args.get("page", 1))
    except ValueError:
        raise BadRequest(description="Invalid page number.")
    q = req.args.get("q", None)
    cat = req.args.get("cat", None)
    status = req.args.get("status", "any")
    if status not in ("any", "active", "archived"):
        raise BadRequest(description="Invalid status.")
    sort = req.args.get("sort", "match")
    if sort not in ("match", "name", "cert_date", "archive_date"):
        raise BadRequest(description="Invalid sort.")

    cursor, categories, count = select_certs(q, cat, status, sort)

    per_page = current_app.config["SEARCH_ITEMS_PER_PAGE"]
    pagination = Pagination(
        page=page,
        per_page=per_page,
        search=True,
        found=count,
        total=mongo.db.pp.count_documents({}),
        css_framework="bootstrap5",
        alignment="center",
        url_callback=callback,
    )
    return {
        "pagination": pagination,
        "profiles": cursor[(page - 1) * per_page : page * per_page],
        "categories": categories,
        "q": q,
        "page": page,
        "status": status,
        "sort": sort,
    }


@pp.route("/search/")
@register_breadcrumb(pp, ".search", "Search")
def search():
    res = process_search(request)
    return render_template(
        "pp/search.html.jinja2",
        **res,
        title=f"Protection Profile [{res['q']}] ({res['page']}) | sec-certs.org",
    )


@pp.route("/search/pagination/")
def search_pagination():
    def callback(**kwargs):
        return url_for(".search", **kwargs)

    res = process_search(request, callback=callback)
    return render_template("pp/search_pagination.html.jinja2", **res)


@pp.route("/<string(length=20):hashid>/")
@register_breadcrumb(
    pp,
    ".entry",
    "",
    dynamic_list_constructor=lambda *args, **kwargs: [{"text": request.view_args["hashid"]}],  # type: ignore
)
def entry(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find profile"):
        raw_doc = mongo.db.pp.find_one({"_id": hashid})
    if raw_doc:
        doc = load(raw_doc)
        with sentry_sdk.start_span(op="mongo", description="Find certs"):
            certs = []
            res = mongo.db.cc.find({"heuristics.protection_profiles._value": {"$elemMatch": {"$eq": hashid}}})
            for cert in res:
                certs.append(load(cert))

        return render_template(
            "pp/entry.html.jinja2",
            profile=doc,
            hashid=hashid,
            certs=certs,
            json=StorageFormat(raw_doc).to_json_mapping(),
        )
    else:
        return abort(404)


@pp.route("/<string(length=20):hashid>/profile.json")
def entry_json(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find profile"):
        doc = mongo.db.pp.find_one({"_id": hashid})
    if doc:
        return send_json_attachment(StorageFormat(doc).to_json_mapping())
    else:
        return abort(404)


@pp.route("/id/<string:profile_id>")
def entry_id(profile_id):
    with sentry_sdk.start_span(op="mongo", description="Find profile"):
        # TODO: This does not work, we have no ids
        doc = mongo.db.pp.find_one({"processed.cc_pp_csvid": profile_id}, {"_id": 1})
    if doc:
        return redirect(url_for("pp.entry", hashid=doc["_id"]))
    else:
        return abort(404)


@pp.route("/name/<string:name>")
def entry_name(name):
    with sentry_sdk.start_span(op="mongo", description="Find profile"):
        ids = list(mongo.db.pp.find({"web_data.name": name}, {"_id": 1}))
    if ids:
        if len(ids) == 1:
            return redirect(url_for("pp.entry", hashid=ids[0]["_id"]))
        else:
            docs = list(map(load, mongo.db.pp.find({"_id": {"$in": list(map(itemgetter("_id"), ids))}})))
            return render_template("pp/disambiguate.html.jinja2", pps=docs, name=name)
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


@sitemap.register_generator
def sitemap_urls():
    yield "pp.index", {}
    yield "pp.dataset", {}
    yield "pp.network", {}
    yield "pp.analysis", {}
    yield "pp.search", {}
    yield "pp.rand", {}
    for doc in mongo.db.pp.find({}, {"_id": 1}):
        yield "pp.entry", {"hashid": doc["_id"]}
