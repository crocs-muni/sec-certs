"""Common Criteria views."""

import random
from operator import itemgetter
from pathlib import Path

import pymongo
import sentry_sdk
from flask import abort, current_app, redirect, render_template, request, send_file, url_for
from flask_breadcrumbs import register_breadcrumb
from flask_cachecontrol import cache_for
from networkx import node_link_data

from .. import cache, mongo
from ..utils import Pagination, add_dots, network_graph_func, send_json_attachment
from . import cc, cc_categories, cc_sars, cc_sfrs, get_cc_analysis, get_cc_graphs, get_cc_map


@cc.app_template_global("get_cc_sar")
def get_cc_sar(sar):
    """Get the long name for a SAR."""
    return cc_sars.get(sar, None)


@cc.route("/sars.json")
@cache.cached(60 * 60)
@cache_for(hours=1)
def sars():
    """Endpoint with CC SAR JSON."""
    return send_json_attachment(cc_sars)


@cc.app_template_global("get_cc_sfr")
def get_cc_sfr(sfr):
    """Get the long name for a SFR."""
    return cc_sfrs.get(sfr, None)


@cc.route("/sfrs.json")
@cache.cached(60 * 60)
@cache_for(hours=1)
def sfrs():
    """Endpoint with CC SFR JSON."""
    return send_json_attachment(cc_sfrs)


@cc.app_template_global("get_cc_category")
def get_cc_category(name):
    """Get the long name for the CC category."""
    return cc_categories.get(name, None)


@cc.route("/categories.json")
@cache.cached(60 * 60)
def categories():
    """Endpoint with CC categories JSON."""
    return send_json_attachment(cc_categories)


@cc.route("/")
@register_breadcrumb(cc, ".", "Common Criteria")
def index():
    """Common criteria index."""
    last_ok_run = mongo.db.cc_log.find_one({"ok": True}, sort=[("start_time", pymongo.DESCENDING)])
    return render_template("cc/index.html.jinja2", last_ok_run=last_ok_run)


@cc.route("/dataset.json")
def dataset():
    """Common criteria dataset API endpoint."""
    dset_path = Path(current_app.instance_path) / current_app.config["DATASET_PATH_CC_OUT"]
    if not dset_path.is_file():
        return abort(404)
    return send_file(
        dset_path,
        as_attachment=True,
        mimetype="application/json",
        attachment_filename="dataset.json",
    )


@cc.route("/network/")
@register_breadcrumb(cc, ".network", "References")
def network():
    """Common criteria references visualization."""
    return render_template("cc/network.html.jinja2", url=url_for(".network_graph"))


@cc.route("/network/graph.json")
@cache.cached(5 * 60)
def network_graph():
    """Common criteria references data."""
    return network_graph_func(get_cc_graphs())


def select_certs(q, cat, status, sort):
    categories = cc_categories.copy()
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
        projection["score"] = {"$meta": "textScore"}
        query["$text"] = {"$search": q}

    if cat is not None:
        selected_cats = []
        for name, category in categories.items():
            if category["id"] in cat:
                selected_cats.append(name)
                category["selected"] = True
            else:
                category["selected"] = False
        query["category"] = {"$in": selected_cats}
    else:
        for category in categories.values():
            category["selected"] = True

    if status is not None and status != "any":
        query["status"] = status

    cursor = mongo.db.cc.find(query, projection)

    if sort == "match" and q is not None and q != "":
        cursor.sort([("score", {"$meta": "textScore"}), ("name", pymongo.ASCENDING)])
    elif sort == "cert_date":
        cursor.sort([("not_valid_before", pymongo.ASCENDING)])
    elif sort == "archive_date":
        cursor.sort([("not_valid_after", pymongo.ASCENDING)])
    else:
        cursor.sort([("name", pymongo.ASCENDING)])

    return cursor, categories


def process_search(req, callback=None):
    page = int(req.args.get("page", 1))
    q = req.args.get("q", None)
    cat = req.args.get("cat", None)
    status = req.args.get("status", "any")
    sort = req.args.get("sort", "match")

    cursor, categories = select_certs(q, cat, status, sort)

    per_page = current_app.config["SEARCH_ITEMS_PER_PAGE"]
    pagination = Pagination(
        page=page,
        per_page=per_page,
        search=True,
        found=cursor.count(),
        total=mongo.db.cc.count_documents({}),
        css_framework="bootstrap4",
        alignment="center",
        url_callback=callback,
    )
    return {
        "pagination": pagination,
        "certs": cursor[(page - 1) * per_page : page * per_page],
        "categories": categories,
        "q": q,
        "page": page,
        "status": status,
        "sort": sort,
    }


@cc.route("/search/")
@register_breadcrumb(cc, ".search", "Search")
def search():
    """Common criteria search."""
    res = process_search(request)
    return render_template(
        "cc/search.html.jinja2",
        **res,
        title=f"Common Criteria [{res['q'] if res['q'] else ''}] ({res['page']}) | seccerts.org",
    )


@cc.route("/search/pagination/")
def search_pagination():
    """Common criteria search (raw pagination)."""

    def callback(**kwargs):
        return url_for(".search", **kwargs)

    res = process_search(request, callback=callback)
    return render_template("cc/search_pagination.html.jinja2", **res)


@cc.route("/analysis/")
@register_breadcrumb(cc, ".analysis", "Analysis")
def analysis():
    """Common criteria analysis results."""
    return render_template("cc/analysis.html.jinja2", analysis=get_cc_analysis())


@cc.route("/random/")
def rand():
    """Common criteria random certificate."""
    current_ids = list(map(itemgetter("_id"), mongo.db.cc.find({}, ["_id"])))
    return redirect(url_for(".entry", hashid=random.choice(current_ids)))


@cc.route("/<string(length=16):hashid>/")
@register_breadcrumb(
    cc, ".entry", "", dynamic_list_constructor=lambda *a, **kw: [{"text": request.view_args["hashid"]}]
)
def entry(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        doc = mongo.db.cc.find_one({"_id": hashid})
    if doc:
        doc = add_dots(doc)
        with sentry_sdk.start_span(op="mongo", description="Find profiles"):
            profiles = {}
            for profile in doc["protection_profiles"]:
                found = mongo.db.pp.find_one({"processed.cc_pp_csvid": profile["pp_ids"]})
                if found:
                    profiles[profile["pp_ids"]] = add_dots(found)
        with sentry_sdk.start_span(op="mongo", description="Find diffs"):
            diffs = list(
                map(add_dots, mongo.db.cc_diff.find({"dgst": hashid}, sort=[("timestamp", pymongo.ASCENDING)]))
            )
        with sentry_sdk.start_span(op="mongo", description="Find CVEs"):
            if doc["heuristics"]["related_cves"]:
                cves = list(map(add_dots, mongo.db.cve.find({"_id": {"$in": doc["heuristics"]["related_cves"]}})))
            else:
                cves = []
        with sentry_sdk.start_span(op="mongo", description="Find CPEs"):
            if doc["heuristics"]["cpe_matches"]:
                cpes = list(map(add_dots, mongo.db.cpe.find({"_id": {"$in": doc["heuristics"]["cpe_matches"]}})))
            else:
                cpes = []
        return render_template(
            "cc/entry.html.jinja2",
            cert=doc,
            hashid=hashid,
            profiles=profiles,
            diffs=diffs,
            cves=cves,
            cpes=cpes,
        )
    else:
        return abort(404)


@cc.route("/<string(length=16):hashid>/graph.json")
def entry_graph_json(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        doc = mongo.db.cc.find_one({"_id": hashid})
    if doc:
        cc_map = get_cc_map()
        if hashid in cc_map.keys():
            network_data = node_link_data(cc_map[hashid])
        else:
            network_data = {}
        return send_json_attachment(network_data)
    else:
        return abort(404)


@cc.route("/<string(length=16):hashid>/cert.json")
def entry_json(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        doc = mongo.db.cc.find_one({"_id": hashid})
    if doc:
        return send_json_attachment(add_dots(doc))
    else:
        return abort(404)


@cc.route("/id/<string:cert_id>")
def entry_id(cert_id):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        doc = mongo.db.cc.find_one({"heuristics.cert_id": cert_id})
    if doc:
        return redirect(url_for("cc.entry", hashid=doc["_id"]))
    else:
        return abort(404)


@cc.route("/name/<string:name>")
def entry_name(name):
    name = name.replace("_", " ")
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        # TODO: make this a "find" instead and if mo are found, render a disambiguation page.
        doc = mongo.db.cc.find_one({"name": name})
    if doc:
        return redirect(url_for("cc.entry", hashid=doc["_id"]))
    else:
        return abort(404)
