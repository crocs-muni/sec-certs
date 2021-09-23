"""Common Criteria views."""

import random
import re
from operator import itemgetter

import pymongo
import sentry_sdk
from flask import (abort, current_app, redirect, render_template, request,
                   url_for)
from flask_breadcrumbs import register_breadcrumb
from networkx import node_link_data

from .. import mongo, cache
from ..utils import (Pagination, add_dots, network_graph_func,
                     send_json_attachment)
from . import (cc, cc_categories, cc_sars, cc_sfrs, get_cc_analysis,
               get_cc_graphs, get_cc_map)


@cc.app_template_global("get_cc_sar")
def get_cc_sar(sar):
    """Get the long name for a SAR."""
    return cc_sars.get(sar, None)


@cc.route("/sars.json")
@cache.cached(60 * 60)
def sars():
    """Endpoint with CC SAR JSON."""
    return send_json_attachment(cc_sars)


@cc.app_template_global("get_cc_sfr")
def get_cc_sfr(sfr):
    """Get the long name for a SFR."""
    return cc_sfrs.get(sfr, None)


@cc.route("/sfrs.json")
@cache.cached(60 * 60)
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
    return render_template("cc/index.html.jinja2", title=f"Common Criteria | seccerts.org")


@cc.route("/network/")
@register_breadcrumb(cc, ".network", "References")
def network():
    return render_template("cc/network.html.jinja2", url=url_for(".network_graph"),
                           title="Common Criteria network | seccerts.org")


@cc.route("/network/graph.json")
@cache.cached(5 * 60)
def network_graph():
    return network_graph_func(get_cc_graphs())


def select_certs(q, cat, status, sort):
    categories = cc_categories.copy()
    query = {}
    projection = {
        "_id": 1,
        "csv_scan.cert_item_name": 1,
        "csv_scan.cert_status": 1,
        "csv_scan.cc_certification_date": 1,
        "csv_scan.cc_archived_date": 1,
        "csv_scan.cc_category": 1,
        "processed.cert_id": 1
    }

    if q is not None and q != "":
        projection["score"] = {"$meta": "textScore"}
        re_q = ".*" + re.escape(q) + ".*"
        query["$or"] = [{"$text": {"$search": q}}, {"csv_scan.cert_item_name": {"$regex": re_q, "$options": "i"}}]

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

    cursor = mongo.db.cc.find(query, projection)

    if sort == "match" and q is not None and q != "":
        cursor.sort([("score", {"$meta": "textScore"}), ("csv_scan.cert_item_name", pymongo.ASCENDING)])
    elif sort == "cert_date":
        cursor.sort([("csv_scan.cc_certification_date", pymongo.ASCENDING)])
    elif sort == "archive_date":
        cursor.sort([("csv_scan.cc_archived_date", pymongo.ASCENDING)])
    else:
        cursor.sort([("csv_scan.cert_item_name", pymongo.ASCENDING)])

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
                            total=mongo.db.cc.count_documents({}),
                            css_framework="bootstrap4", alignment="center",
                            url_callback=callback)
    return {
        "pagination": pagination,
        "certs": cursor[(page - 1) * per_page:page * per_page],
        "categories": categories,
        "q": q,
        "page": page,
        "status": status,
        "sort": sort
    }


@cc.route("/search/")
@register_breadcrumb(cc, ".search", "Search")
def search():
    res = process_search(request)
    return render_template("cc/search.html.jinja2", **res,
                           title=f"Common Criteria [{res['q']}] ({res['page']}) | seccerts.org")


@cc.route("/search/pagination/")
def search_pagination():
    def callback(**kwargs):
        return url_for(".search", **kwargs)

    res = process_search(request, callback=callback)
    return render_template("cc/search_pagination.html.jinja2", **res)


@cc.route("/analysis/")
@register_breadcrumb(cc, ".analysis", "Analysis")
def analysis():
    return render_template("cc/analysis.html.jinja2", analysis=get_cc_analysis())


@cc.route("/random/")
def rand():
    current_ids = list(map(itemgetter("_id"), mongo.db.cc.find({}, ["_id"])))
    return redirect(url_for(".entry", hashid=random.choice(current_ids)))


@cc.route("/<string(length=20):hashid>/")
@register_breadcrumb(cc, ".entry", "", dynamic_list_constructor=lambda *args, **kwargs: [{"text": request.view_args["hashid"]}])
def entry(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        doc = mongo.db.cc.find_one({"_id": hashid})
        profiles = {}
        if "processed" in doc and "cc_pp_id" in doc["processed"]:
            found = mongo.db.pp.find_one({"processed.cc_pp_csvid": doc["processed"]["cc_pp_id"]})
            if found:
                profiles[doc["processed"]["cc_pp_id"]] = add_dots(found)
        if "csv_scan" in doc and "cc_protection_profiles" in doc["csv_scan"]:
            ids = doc["csv_scan"]["cc_protection_profiles"].split(",")
            for id in ids:
                found = mongo.db.pp.find_one({"processed.cc_pp_csvid": id})
                if found:
                    profiles[id] = add_dots(found)
    if doc:
        return render_template("cc/entry.html.jinja2", cert=add_dots(doc), hashid=hashid, profiles=profiles)
    else:
        return abort(404)


@cc.route("/<string(length=20):hashid>/graph.json")
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


@cc.route("/<string(length=20):hashid>/cert.json")
def entry_json(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        doc = mongo.db.cc.find_one({"_id": hashid})
    if doc:
        return send_json_attachment(add_dots(doc))
    else:
        return abort(404)
