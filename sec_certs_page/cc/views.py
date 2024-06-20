"""Common Criteria views."""
import random
import re
from operator import itemgetter
from pathlib import Path
from urllib.parse import urlencode

import pymongo
import sentry_sdk
from feedgen.feed import FeedGenerator
from flask import Response, abort, current_app, redirect, render_template, request, send_file, url_for
from flask_breadcrumbs import register_breadcrumb
from flask_cachecontrol import cache_for
from markupsafe import Markup
from networkx import node_link_data
from pytz import timezone
from werkzeug.exceptions import BadRequest
from werkzeug.utils import safe_join

from .. import cache, mongo, sitemap
from ..common.diffs import render_compare
from ..common.objformats import StorageFormat, load
from ..common.views import (
    entry_download_certificate_pdf,
    entry_download_certificate_txt,
    entry_download_files,
    entry_download_report_pdf,
    entry_download_report_txt,
    entry_download_target_pdf,
    entry_download_target_txt,
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
from .search import CCBasicSearch, CCFulltextSearch
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


@cc.route("/cc.tar.gz")
def dataset_archive():
    """Common criteria dataset archive API endpoint."""
    archive_path = Path(current_app.instance_path) / current_app.config["DATASET_PATH_CC_ARCHIVE"]
    if not archive_path.is_file():
        return abort(404)
    return send_file(
        archive_path,
        as_attachment=True,
        mimetype="application/gzip",
        download_name="cc.tar.gz",
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


@cc.route("/schemes.json")
def schemes():
    """Common criteria scheme dataset API endpoint."""
    dset_path = Path(current_app.instance_path) / current_app.config["DATASET_PATH_CC_OUT_SCHEME"]
    if not dset_path.is_file():
        return abort(404)
    return send_file(
        dset_path,
        as_attachment=True,
        mimetype="application/json",
        download_name="schemes.json",
    )


@cc.route("/network/")
@register_breadcrumb(cc, ".network", "References")
def network():
    """Common criteria references visualization."""
    query = None
    if request.args:
        query = urlencode({Markup.escape(key): Markup.escape(value) for key, value in request.args.items()})
    return render_template("cc/network.html.jinja2", query=query)


@cc.route("/network/graph.json")
def network_graph():
    """Common criteria references data."""
    if "search" in request.args:
        args = {Markup(key).unescape(): Markup(value).unescape() for key, value in request.args.items()}
        if request.args["search"] == "basic":
            args = CCBasicSearch.parse_args(args)
            del args["page"]
            certs, count, timeline = CCBasicSearch.select_certs(**args)
        elif request.args["search"] == "fulltext":
            args = CCFulltextSearch.parse_args(args)
            del args["page"]
            certs, count = CCFulltextSearch.select_certs(**args)
        elif request.args["search"] == "cve":
            cve_id = args["cve"]
            certs = list(map(load, mongo.db.cc.find({"heuristics.related_cves._value": cve_id})))
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
    res = CCBasicSearch.process_search(request)
    return render_template(
        "cc/search/index.html.jinja2",
        **res,
        title=f"Common Criteria [{res['q'] if res['q'] else ''}] ({res['page']}) | sec-certs.org",
    )


@cc.route("/search/results/")
def search_results():
    """Common criteria search (raw results, pagination + timeline)."""

    def callback(**kwargs):
        return url_for(".search", **kwargs)

    res = CCBasicSearch.process_search(request, callback=callback)
    return render_template("cc/search/results.html.jinja2", **res)


@cc.route("/ftsearch/")
@register_breadcrumb(cc, ".fulltext_search", "Fulltext search")
def fulltext_search():
    """Fulltext search for Common Criteria."""
    res = CCFulltextSearch.process_search(request)
    return render_template("cc/search/fulltext.html.jinja2", **res)


@cc.route("/compare/<string(length=16):one_hashid>/<string(length=16):other_hashid>/")
def compare(one_hashid: str, other_hashid: str):
    with sentry_sdk.start_span(op="mongo", description="Find certs"):
        raw_one = mongo.db.cc.find_one({"_id": one_hashid}, {"_id": 0})
        raw_other = mongo.db.cc.find_one({"_id": other_hashid}, {"_id": 0})
    if not raw_one or not raw_other:
        return abort(404)
    doc_one = load(raw_one)
    doc_other = load(raw_other)
    k1_order = [
        "name",
        "category",
        "not_valid_before",
        "not_valid_after",
        "scheme",
        "st_link",
        "status",
        "manufacturer",
        "manufacturer_web",
        "security_level",
        "report_link",
        "cert_link",
        "protection_profiles",
        "maintenance_updates",
        "state",
        "heuristics",
        "pdf_data",
        "_type",
        "dgst",
    ]
    return render_template(
        "common/compare.html.jinja2",
        changes=render_compare(doc_one, doc_other, k1_order),
        cert_one=doc_one,
        cert_other=doc_other,
        name_one=doc_one["name"],
        name_other=doc_other["name"],
        hashid_one=one_hashid,
        hashid_other=other_hashid,
    )


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
            diffs = list(mongo.db.cc_diff.find({"dgst": hashid}, sort=[("timestamp", pymongo.DESCENDING)]))
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


@cc.route("/<string(length=16):hashid>/cert.txt")
def entry_cert_txt(hashid):
    return entry_download_certificate_txt("cc", hashid, current_app.config["DATASET_PATH_CC_DIR"])


@cc.route("/<string(length=16):hashid>/cert.pdf")
def entry_cert_pdf(hashid):
    return entry_download_certificate_pdf("cc", hashid, current_app.config["DATASET_PATH_CC_DIR"])


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


@cc.route("/<string(length=16):hashid>/feed.xml")
def entry_feed(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        raw_doc = mongo.db.cc.find_one({"_id": hashid})
    if raw_doc:
        tz = timezone("Europe/Prague")
        doc = load(raw_doc)
        entry_url = url_for(".entry", hashid=hashid, _external=True)
        renderer = CCRenderer()
        with sentry_sdk.start_span(op="mongo", description="Find and render diffs"):
            diffs = list(map(load, mongo.db.cc_diff.find({"dgst": hashid}, sort=[("timestamp", pymongo.ASCENDING)])))
            diff_renders = list(map(lambda x: renderer.render_diff(hashid, doc, x, linkback=True), diffs))
        fg = FeedGenerator()
        fg.id(request.base_url)
        fg.title(doc["name"])
        fg.author({"name": "sec-certs", "email": "webmaster@sec-certs.org"})
        fg.link({"href": entry_url, "rel": "alternate"})
        fg.link({"href": request.base_url, "rel": "self"})
        fg.icon(url_for("static", filename="img/favicon.png", _external=True))
        fg.logo(url_for("static", filename="img/cc_card.png", _external=True))
        fg.language("en")
        last_update = None
        for diff, render in zip(diffs, diff_renders):
            date = tz.localize(diff["timestamp"])
            fe = fg.add_entry()
            fe.author({"name": "sec-certs", "email": "webmaster@sec-certs.org"})
            fe.title(
                {
                    "back": "Certificate reappeared",
                    "change": "Certificate changed",
                    "new": "New certificate",
                    "remove": "Certificate removed",
                }[diff["type"]]
            )
            fe.id(entry_url + "/" + str(diff["_id"]))
            s = str(render)
            stripped = re.sub("[^\u0020-\uD7FF\u0009\u000A\u000D\uE000-\uFFFD\U00010000-\U0010FFFF]+", "", s)
            fe.content(stripped, type="html")
            fe.published(date)
            fe.updated(date)
            if last_update is None or date > last_update:
                last_update = date

        fg.lastBuildDate(last_update)
        fg.updated(last_update)
        return Response(fg.atom_str(pretty=True), mimetype="application/atom+xml")
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
    yield "cc.maintenance_updates", {}
    yield "cc.network", {}
    yield "cc.analysis", {}
    yield "cc.search", {}
    yield "cc.fulltext_search", {}
    yield "cc.rand", {}
    for doc in mongo.db.cc.find({}, {"_id": 1}):
        yield "cc.entry", {"hashid": doc["_id"]}
