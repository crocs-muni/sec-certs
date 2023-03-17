"""Common Criteria views."""
import random
from operator import itemgetter
from pathlib import Path
from urllib.parse import urlencode

import pymongo
import sentry_sdk
from flask import abort, current_app, redirect, render_template, request, send_file, url_for
from flask_breadcrumbs import register_breadcrumb
from flask_cachecontrol import cache_for
from markupsafe import escape
from networkx import node_link_data
from werkzeug.exceptions import BadRequest
from werkzeug.utils import safe_join

from .. import cache, mongo, sitemap
from ..common.objformats import StorageFormat, load
from ..common.views import (
    entry_download_files,
    entry_download_report_pdf,
    entry_download_report_txt,
    entry_download_target_pdf,
    entry_download_target_txt,
    entry_file_path,
    network_graph_func,
    send_json_attachment,
)
from . import (
    cc,
    cc_categories,
    cc_eals,
    cc_reference_types,
    cc_sars,
    cc_sfrs,
    cc_status,
    get_cc_analysis,
    get_cc_graphs,
    get_cc_map,
)
from .search import BasicSearch, FulltextSearch
from .tasks import CCRenderer


@cc.app_template_global("get_cc_sar")
def get_cc_sar(sar):
    """Get the long name for a SAR."""
    return cc_sars.get(sar, None)


@cc.route("/sars.json")
@cache.cached(60 * 60)
@cache_for(days=7)
def sars():
    """Endpoint with CC SAR JSON."""
    return send_json_attachment(cc_sars)


@cc.app_template_global("get_cc_sfr")
def get_cc_sfr(sfr):
    """Get the long name for a SFR."""
    return cc_sfrs.get(sfr, None)


@cc.route("/sfrs.json")
@cache.cached(60 * 60)
@cache_for(days=7)
def sfrs():
    """Endpoint with CC SFR JSON."""
    return send_json_attachment(cc_sfrs)


@cc.app_template_global("get_cc_category")
def get_cc_category(name):
    """Get the long name for the CC category."""
    return cc_categories.get(name, None)


@cc.route("/categories.json")
@cache.cached(60 * 60)
@cache_for(days=7)
def categories():
    """Endpoint with CC categories JSON."""
    return send_json_attachment(cc_categories)


@cc.app_template_global("get_cc_eal")
def get_cc_eal(name):
    """Get the long name for the CC EAL."""
    return cc_eals.get(name, None)


@cc.route("/eals.json")
@cache.cached(60 * 60)
@cache_for(days=7)
def eals():
    """Endpoint with CC EALs JSON."""
    return send_json_attachment(cc_eals)


@cc.route("/status.json")
@cache.cached(60 * 60)
@cache_for(days=7)
def statuses():
    """Endpoint with CC status JSON."""
    return send_json_attachment(cc_status)


@cc.route("/reference_types.json")
@cache.cached(60 * 60)
@cache_for(days=7)
def reference_types():
    """Endpoint with CC reference_types JSON."""
    return send_json_attachment(cc_reference_types)


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
        download_name="dataset.json",
    )


@cc.route("/maintenance_updates.json")
def maintenance_updates():
    """Common criteria maintenance updates dataset API endpoint."""
    dset_path = Path(current_app.instance_path) / current_app.config["DATASET_PATH_CC_OUT_MU"]
    if not dset_path.is_file():
        return abort(404)
    return send_file(
        dset_path,
        as_attachment=True,
        mimetype="application/json",
        download_name="maintenance_updates.json",
    )


@cc.route("/network/")
@register_breadcrumb(cc, ".network", "References")
def network():
    """Common criteria references visualization."""
    query = None
    if request.args:
        query = urlencode({escape(key): escape(value) for key, value in request.args.items()})
    return render_template("cc/network.html.jinja2", query=query)


@cc.route("/network/graph.json")
def network_graph():
    """Common criteria references data."""
    if "search" in request.args:
        if request.args["search"] == "basic":
            args = BasicSearch.parse_args(request.args)
            del args["page"]
            certs, count = BasicSearch.select_certs(**args)
        elif request.args["search"] == "fulltext":
            args = FulltextSearch.parse_args(request.args)
            del args["page"]
            certs, count = FulltextSearch.select_certs(**args)
        else:
            raise BadRequest("Invalid search query.")
        component_map = get_cc_map()
        components = {}
        ids = []
        for cert in certs:
            if cert["_id"] not in component_map:
                continue
            ids.append(cert["_id"])
            component = component_map[cert["_id"]]
            if id(component) not in components:
                components[id(component)] = component
        return network_graph_func(list(components.values()), highlighted=ids)
    return network_graph_func(get_cc_graphs())


@cc.route("/search/")
@register_breadcrumb(cc, ".search", "Search")
def search():
    """Common criteria search."""
    res = BasicSearch.process_search(request)
    return render_template(
        "cc/search/index.html.jinja2",
        **res,
        title=f"Common Criteria [{res['q'] if res['q'] else ''}] ({res['page']}) | seccerts.org",
    )


@cc.route("/search/pagination/")
def search_pagination():
    """Common criteria search (raw pagination)."""

    def callback(**kwargs):
        return url_for(".search", **kwargs)

    res = BasicSearch.process_search(request, callback=callback)
    return render_template("cc/search/pagination.html.jinja2", **res)


@cc.route("/ftsearch/")
@register_breadcrumb(cc, ".fulltext_search", "Fulltext search")
def fulltext_search():
    """Fulltext search for Common Criteria."""
    res = FulltextSearch.process_search(request)
    return render_template("cc/search/fulltext.html.jinja2", **res)


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


@cc.route("/<string(length=20):old_id>/")
@cc.route("/<string(length=20):old_id>/<path:npath>")
def entry_old(old_id, npath=None):
    with sentry_sdk.start_span(op="mongo", description="Find id map entry."):
        id_map = mongo.db.cc_old.find_one({"_id": old_id})
    if id_map:
        redir_path = url_for("cc.entry", hashid=id_map["hashid"])
        if npath:
            redir_path = safe_join(redir_path, npath)
        return redirect(redir_path)
    else:
        return abort(404)


@cc.route("/<string(length=16):hashid>/")
@register_breadcrumb(
    cc, ".entry", "", dynamic_list_constructor=lambda *a, **kw: [{"text": request.view_args["hashid"]}]  # type: ignore
)
def entry(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        raw_doc = mongo.db.cc.find_one({"_id": hashid}, {"_id": 0})
    if raw_doc:
        doc = load(raw_doc)
        with sentry_sdk.start_span(op="mongo", description="Find profiles"):
            profiles = {}
            for profile in doc["protection_profiles"]:
                if not profile["pp_ids"]:
                    continue
                found = mongo.db.pp.find_one({"processed.cc_pp_csvid": {"$in": list(profile["pp_ids"])}})
                if found:
                    profiles[profile["pp_ids"]] = load(found)
        renderer = CCRenderer()
        with sentry_sdk.start_span(op="mongo", description="Find and render diffs"):
            diffs = list(mongo.db.cc_diff.find({"dgst": hashid}, sort=[("timestamp", pymongo.ASCENDING)]))
            diff_jsons = list(map(lambda x: StorageFormat(x).to_json_mapping(), diffs))
            diffs = list(map(load, diffs))
            diff_renders = list(map(lambda x: renderer.render_diff(hashid, doc, x, linkback=False), diffs))
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
            local_files = entry_download_files(hashid, current_app.config["DATASET_PATH_CC_DIR"])
        with sentry_sdk.start_span(op="network", description="Find network"):
            cc_map = get_cc_map()
            cert_network = cc_map.get(hashid, {})
        return render_template(
            "cc/entry/index.html.jinja2",
            cert=doc,
            hashid=hashid,
            profiles=profiles,
            diffs=diffs,
            diff_jsons=diff_jsons,
            diff_renders=diff_renders,
            cves=cves,
            cpes=cpes,
            local_files=local_files,
            json=StorageFormat(raw_doc).to_json_mapping(),
            network=cert_network,
        )
    else:
        return abort(404)


@cc.route("/<string(length=16):hashid>/target.txt")
def entry_target_txt(hashid):
    return entry_download_target_txt("cc", hashid, current_app.config["DATASET_PATH_CC_DIR"])


@cc.route("/<string(length=16):hashid>/target.pdf")
def entry_target_pdf(hashid):
    return entry_download_target_pdf("cc", hashid, current_app.config["DATASET_PATH_CC_DIR"])


@cc.route("/<string(length=16):hashid>/report.txt")
def entry_report_txt(hashid):
    return entry_download_report_txt("cc", hashid, current_app.config["DATASET_PATH_CC_DIR"])


@cc.route("/<string(length=16):hashid>/report.pdf")
def entry_report_pdf(hashid):
    return entry_download_report_pdf("cc", hashid, current_app.config["DATASET_PATH_CC_DIR"])


@cc.route("/<string(length=16):hashid>/graph.json")
def entry_graph_json(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        doc = mongo.db.cc.find_one({"_id": hashid}, {"_id": 1})
    if doc:
        cc_map = get_cc_map()
        if hashid in cc_map.keys():
            network_data = node_link_data(cc_map[hashid])
        else:
            network_data = {}
        network_data["highlighted"] = [hashid]
        return send_json_attachment(network_data)
    else:
        return abort(404)


@cc.route("/<string(length=16):hashid>/cert.json")
def entry_json(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        doc = mongo.db.cc.find_one({"_id": hashid})
    if doc:
        return send_json_attachment(StorageFormat(doc).to_json_mapping())
    else:
        return abort(404)


@cc.route("/id/<string:cert_id>")
def entry_id(cert_id):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        doc = mongo.db.cc.find_one({"heuristics.cert_id": cert_id}, {"_id": 1})
    if doc:
        return redirect(url_for("cc.entry", hashid=doc["_id"]))
    else:
        return abort(404)


@cc.route("/name/<string:name>")
def entry_name(name):
    with sentry_sdk.start_span(op="mongo", description="Find certs"):
        ids = list(mongo.db.cc.find({"name": name}, {"_id": 1}))
    if ids:
        if len(ids) == 1:
            return redirect(url_for("cc.entry", hashid=ids[0]["_id"]))
        else:
            docs = list(map(load, mongo.db.cc.find({"_id": {"$in": list(map(itemgetter("_id"), ids))}})))
            return render_template("cc/entry/disambiguate.html.jinja2", certs=docs, name=name)
    else:
        return abort(404)


@sitemap.register_generator
def sitemap_urls():
    yield "cc.index", {}
    yield "cc.dataset", {}
    yield "cc.network", {}
    yield "cc.analysis", {}
    yield "cc.search", {}
    yield "cc.rand", {}
    for doc in mongo.db.cc.find({}, {"_id": 1}):
        yield "cc.entry", {"hashid": doc["_id"]}
