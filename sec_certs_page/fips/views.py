"""FIPS views."""

import random
from datetime import datetime
from operator import itemgetter
from pathlib import Path

import pymongo
import sentry_sdk
from flask import abort, current_app, redirect, render_template, request, send_file, url_for
from flask_breadcrumbs import register_breadcrumb
from networkx import node_link_data
from werkzeug.exceptions import BadRequest
from werkzeug.utils import safe_join

from .. import cache, mongo
from ..common.objformats import StorageFormat, load
from ..common.views import (
    Pagination,
    entry_download_files,
    entry_download_target_pdf,
    entry_download_target_txt,
    network_graph_func,
    send_json_attachment,
)
from . import fips, fips_types, get_fips_graphs, get_fips_map


@fips.app_template_global("get_fips_type")
def get_fips_type(name):
    return fips_types.get(name, None)


@fips.route("/types.json")
@cache.cached(60 * 60)
def types():
    return send_json_attachment(fips_types)


@fips.route("/")
@register_breadcrumb(fips, ".", "FIPS 140")
def index():
    last_ok_run = mongo.db.fips_log.find_one({"ok": True}, sort=[("start_time", pymongo.DESCENDING)])
    return render_template(
        "fips/index.html.jinja2",
        title="FIPS 140 | seccerts.org",
        last_ok_run=last_ok_run,
    )


@fips.route("/dataset.json")
def dataset():
    dset_path = Path(current_app.instance_path) / current_app.config["DATASET_PATH_FIPS_OUT"]
    if not dset_path.is_file():
        return abort(404)
    return send_file(
        dset_path,
        as_attachment=True,
        mimetype="application/json",
        attachment_filename="dataset.json",
    )


@fips.route("/network/")
@register_breadcrumb(fips, ".network", "References")
def network():
    return render_template(
        "fips/network.html.jinja2",
        url=url_for(".network_graph"),
        title="FIPS 140 network | seccerts.org",
    )


@fips.route("/network/graph.json")
@cache.cached(5 * 60)
def network_graph():
    return network_graph_func(get_fips_graphs())


def select_certs(q, cat, status, sort):
    categories = fips_types.copy()
    query = {}
    projection = {
        "_id": 1,
        "cert_id": 1,
        "web_scan.module_name": 1,
        "web_scan.status": 1,
        "web_scan.level": 1,
        "web_scan.vendor": 1,
        "web_scan.module_type": 1,
        "web_scan.date_validation": 1,
        "web_scan.date_sunset": 1,
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
        query["web_scan.module_type"] = {"$in": selected_cats}
    else:
        for category in categories.values():
            category["selected"] = True

    if status is not None and status != "Any":
        query["web_scan.status"] = status

    cursor = mongo.db.fips.find(query, projection)
    count = mongo.db.fips.count_documents(query)

    if sort == "match" and q is not None and q != "":
        cursor.sort(
            [
                ("score", {"$meta": "textScore"}),
                ("web_scan.module_name", pymongo.ASCENDING),
            ]
        )
    elif sort == "number":
        cursor.sort([("cert_id", pymongo.ASCENDING)])
    elif sort == "first_cert_date":
        cursor.sort([("web_scan.date_validation.0", pymongo.ASCENDING)])
    elif sort == "last_cert_date":
        cursor.sort([("web_scan.date_validation", pymongo.ASCENDING)])
    elif sort == "sunset_date":
        cursor.sort([("web_scan.date_sunset", pymongo.ASCENDING)])
    elif sort == "level":
        cursor.sort([("web_scan.level", pymongo.ASCENDING)])
    elif sort == "vendor":
        cursor.sort([("web_scan.vendor", pymongo.ASCENDING)])
    return cursor, categories, count


def process_search(req, callback=None):
    try:
        page = int(req.args.get("page", 1))
    except ValueError:
        raise BadRequest(description="Invalid page number.")
    q = req.args.get("q", None)
    cat = req.args.get("cat", None)
    status = req.args.get("status", "Any")
    if status not in ("Any", "Active", "Historical", "Revoked"):
        raise BadRequest(description="Invalid status.")
    sort = req.args.get("sort", "match")
    if sort not in ("match", "number", "first_cert_date", "last_cert_date", "sunset_date", "level", "vendor"):
        raise BadRequest(description="Invalid sort.")

    cursor, categories, count = select_certs(q, cat, status, sort)

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
        "q": q,
        "page": page,
        "status": status,
        "sort": sort,
    }


@fips.route("/search/")
@register_breadcrumb(fips, ".search", "Search")
def search():
    res = process_search(request)
    return render_template(
        "fips/search.html.jinja2",
        **res,
        title=f"FIPS 140 [{res['q']}] ({res['page']}) | seccerts.org",
    )


@fips.route("/search/pagination/")
def search_pagination():
    def callback(**kwargs):
        return url_for(".search", **kwargs)

    res = process_search(request, callback=callback)
    return render_template("fips/search_pagination.html.jinja2", **res)


@fips.route("/analysis/")
@register_breadcrumb(fips, ".analysis", "Analysis")
def analysis():
    return render_template("fips/analysis.html.jinja2")


@fips.route("/mip/")
@register_breadcrumb(fips, ".mip", "MIP")
def mip_index():
    try:
        page = int(request.args.get("page", 1))
    except ValueError:
        raise BadRequest(description="Invalid page number.")

    per_page = current_app.config["SEARCH_ITEMS_PER_PAGE"]
    mip_snapshots = list(
        mongo.db.fips_mip.find({}).sort([("_id", pymongo.DESCENDING)]).skip((page - 1) * per_page).limit(per_page)
    )
    count = mongo.db.fips_mip.count_documents({})

    pagination = Pagination(
        page=page,
        per_page=per_page,
        search=True,
        found=len(mip_snapshots),
        total=count,
        css_framework="bootstrap5",
        alignment="center",
    )
    return render_template("fips/mip_index.html.jinja2", snapshots=mip_snapshots, pagination=pagination)


@fips.route("/mip/<ObjectId:id>")
@register_breadcrumb(
    fips,
    ".mip.snapshot",
    "",
    dynamic_list_constructor=lambda *args, **kwargs: [{"text": request.view_args["id"]}],
)
def mip_snapshot(id):
    snapshot = mongo.db.fips_mip.find_one_or_404(id)
    return render_template("fips/mip.html.jinja2", snapshot=snapshot)


@fips.route("/mip/entry/<path:name>")
@register_breadcrumb(
    fips,
    ".mip.entry",
    "",
    dynamic_list_constructor=lambda *args, **kwargs: [{"text": request.view_args["name"]}],
)
def mip_entry(name):
    snapshots = list(mongo.db.fips_mip.find({"entries.module_name": name}).sort([("timestamp", pymongo.ASCENDING)]))
    if not snapshots:
        return abort(404)
    for snap in snapshots:
        snap["entries"] = list(filter(lambda entry: entry["module_name"] == name, snap["entries"]))
    present = datetime.fromisoformat(snapshots[-1]["timestamp"]) - datetime.fromisoformat(snapshots[0]["timestamp"])
    return render_template("fips/mip_entry.html.jinja2", snapshots=snapshots, name=name, present=present)


@fips.route("/iut/")
@register_breadcrumb(fips, ".iut", "IUT")
def iut_index():
    try:
        page = int(request.args.get("page", 1))
    except ValueError:
        raise BadRequest(description="Invalid page number.")

    per_page = current_app.config["SEARCH_ITEMS_PER_PAGE"]
    iut_snapshots = list(
        mongo.db.fips_iut.find({}).sort([("_id", pymongo.DESCENDING)]).skip((page - 1) * per_page).limit(per_page)
    )
    count = mongo.db.fips_iut.count_documents({})

    pagination = Pagination(
        page=page,
        per_page=per_page,
        search=True,
        found=len(iut_snapshots),
        total=count,
        css_framework="bootstrap5",
        alignment="center",
    )
    return render_template("fips/iut_index.html.jinja2", snapshots=iut_snapshots, pagination=pagination)


@fips.route("/iut/<ObjectId:id>")
@register_breadcrumb(
    fips,
    ".iut.snapshot",
    "",
    dynamic_list_constructor=lambda *args, **kwargs: [{"text": request.view_args["id"]}],
)
def iut_snapshot(id):
    snapshot = mongo.db.fips_iut.find_one_or_404(id)
    return render_template("fips/iut.html.jinja2", snapshot=snapshot)


@fips.route("/iut/entry/<path:name>")
@register_breadcrumb(
    fips,
    ".iut.entry",
    "",
    dynamic_list_constructor=lambda *args, **kwargs: [{"text": request.view_args["name"]}],
)
def iut_entry(name):
    snapshots = list(mongo.db.fips_iut.find({"entries.module_name": name}).sort([("timestamp", pymongo.ASCENDING)]))
    if not snapshots:
        return abort(404)
    for snap in snapshots:
        snap["entries"] = list(filter(lambda entry: entry["module_name"] == name, snap["entries"]))
    present = datetime.fromisoformat(snapshots[-1]["timestamp"]) - datetime.fromisoformat(snapshots[0]["timestamp"])
    return render_template("fips/iut_entry.html.jinja2", snapshots=snapshots, name=name, present=present)


@fips.route("/random/")
def rand():
    current_ids = list(map(itemgetter("_id"), mongo.db.fips.find({}, ["_id"])))
    return redirect(url_for(".entry", hashid=random.choice(current_ids)))


@fips.route("/<string(length=20):old_id>/")
@fips.route("/<string(length=20):old_id>/<path:npath>")
def entry_old(old_id, npath=None):
    with sentry_sdk.start_span(op="mongo", description="Find id map entry."):
        id_map = mongo.db.fips_old.find_one({"_id": old_id})
    if id_map:
        redir_path = url_for("fips.entry", hashid=id_map["hashid"])
        if npath:
            redir_path = safe_join(redir_path, npath)
        return redirect(redir_path)
    else:
        return abort(404)


@fips.route("/<string(length=16):hashid>/")
@register_breadcrumb(
    fips,
    ".entry",
    "",
    dynamic_list_constructor=lambda *args, **kwargs: [{"text": request.view_args["hashid"]}],
)
def entry(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        raw_doc = mongo.db.fips.find_one({"_id": hashid})
    if raw_doc:
        doc = load(raw_doc)
        with sentry_sdk.start_span(op="mongo", description="Find CVEs"):
            if doc["heuristics"]["related_cves"]:
                cves = list(map(load, mongo.db.cve.find({"_id": {"$in": list(doc["heuristics"]["related_cves"])}})))
            else:
                cves = []
        with sentry_sdk.start_span(op="mongo", description="Find CPEs"):
            if doc["heuristics"]["cpe_matches"]:
                cpes = list(map(load, mongo.db.cpe.find({"_id": {"$in": list(doc["heuristics"]["cpe_matches"])}})))
            else:
                cpes = []
        with sentry_sdk.start_span(op="files", description="Find local files"):
            local_files = entry_download_files(
                hashid, current_app.config["DATASET_PATH_FIPS_DIR"], documents=("target",)
            )
        return render_template(
            "fips/entry.html.jinja2",
            cert=doc,
            hashid=hashid,
            cves=cves,
            cpes=cpes,
            local_files=local_files,
            json=StorageFormat(raw_doc).to_json_mapping(),
        )
    else:
        return abort(404)


@fips.route("/<string(length=16):hashid>/target.txt")
def entry_target_txt(hashid):
    return entry_download_target_txt("fips", hashid, current_app.config["DATASET_PATH_FIPS_DIR"])


@fips.route("/<string(length=16):hashid>/target.pdf")
def entry_target_pdf(hashid):
    return entry_download_target_pdf("fips", hashid, current_app.config["DATASET_PATH_FIPS_DIR"])


@fips.route("/<string(length=16):hashid>/graph.json")
def entry_graph_json(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        doc = mongo.db.fips.find_one({"_id": hashid})
    if doc:
        fips_map = get_fips_map()
        if hashid in fips_map.keys():
            network_data = node_link_data(fips_map[hashid])
        else:
            network_data = {}
        return send_json_attachment(network_data)
    else:
        return abort(404)


@fips.route("/<string(length=16):hashid>/cert.json")
def entry_json(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        doc = mongo.db.fips.find_one({"_id": hashid})
    if doc:
        return send_json_attachment(StorageFormat(doc).to_json_mapping())
    else:
        return abort(404)


@fips.route("/id/<string:cert_id>")
def entry_id(cert_id):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        doc = mongo.db.fips.find_one({"cert_id": cert_id}, {"_id": 1})
    if doc:
        return redirect(url_for("fips.entry", hashid=doc["_id"]))
    else:
        return abort(404)


@fips.route("/name/<string:name>")
def entry_name(name):
    with sentry_sdk.start_span(op="mongo", description="Find certs"):
        ids = list(mongo.db.fips.find({"web_scan.module_name": name}, {"_id": 1}))
    if ids:
        if len(ids) == 1:
            return redirect(url_for("fips.entry", hashid=ids[0]["_id"]))
        else:
            docs = list(map(load, mongo.db.fips.find({"_id": {"$in": list(map(itemgetter("_id"), ids))}})))
            return render_template("fips/disambiguate.html.jinja2", certs=docs, name=name)
    else:
        return abort(404)
