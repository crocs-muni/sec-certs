"""Common Criteria views."""

import random
from functools import wraps
from operator import itemgetter
from urllib.parse import urlencode

import pymongo
import sentry_sdk
from flask import abort, current_app, redirect, render_template, request, url_for
from flask_cachecontrol import cache_for
from flask_login import current_user
from markupsafe import Markup
from networkx import node_link_data
from periodiq import cron
from werkzeug.exceptions import BadRequest
from werkzeug.utils import safe_join

from .. import cache, mongo, sitemap
from ..common.diffs import cc_diff_method, render_compare
from ..common.feed import Feed
from ..common.objformats import StorageFormat, load
from ..common.views import (
    entry_download_certificate_pdf,
    entry_download_certificate_txt,
    entry_download_files,
    entry_download_report_pdf,
    entry_download_report_txt,
    entry_download_target_pdf,
    entry_download_target_txt,
    expires_at,
    network_graph_func,
    register_breadcrumb,
    send_cacheable_instance_file,
    send_json_attachment,
    sitemap_cert_pipeline,
)
from . import cc, cc_categories, cc_eals, cc_reference_types, cc_sars, cc_schemes, cc_sfrs, cc_status, get_cc_references
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
    return render_template("cc/index.html.jinja2")


@cc.route("/dataset.json")
def dataset():
    """Common criteria dataset API endpoint."""
    return send_cacheable_instance_file(current_app.config["DATASET_PATH_CC_OUT"], "application/json", "dataset.json")


@cc.route("/cc.tar.gz")
def dataset_archive():
    """Common criteria dataset archive API endpoint."""
    return send_cacheable_instance_file(current_app.config["DATASET_PATH_CC_ARCHIVE"], "application/gzip", "cc.tar.gz")


@cc.route("/maintenance_updates.json")
def maintenance_updates():
    """Common criteria maintenance updates dataset API endpoint."""
    return send_cacheable_instance_file(
        current_app.config["DATASET_PATH_CC_OUT_MU"], "application/json", "maintenance_updates.json"
    )


@cc.route("/schemes.json")
def schemes():
    """Common criteria scheme dataset API endpoint."""
    return send_cacheable_instance_file(
        current_app.config["DATASET_PATH_CC_OUT_SCHEME"], "application/json", "schemes.json"
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
    cc_references = get_cc_references()
    if "search" in request.args:
        args = {Markup(key).unescape(): Markup(value).unescape() for key, value in request.args.items()}
        if request.args["search"] == "basic":
            args = CCBasicSearch.parse_args(args)
            if "page" in args:
                del args["page"]
            certs, count, timeline = CCBasicSearch.select_certs(**args)
        elif request.args["search"] == "fulltext":
            args = CCFulltextSearch.parse_args(args)
            if "page" in args:
                del args["page"]
            certs, count = CCFulltextSearch.select_certs(**args)
        elif request.args["search"] == "cve":
            if "cve" not in args:
                raise BadRequest("Missing 'cve' parameter for CVE search.")
            cve_id = args["cve"]
            certs = list(map(load, mongo.db.cc.find({"heuristics.related_cves._value": cve_id})))
        else:
            raise BadRequest("Invalid search query.")
        components = {}
        ids = []
        for cert in certs:
            if cert["_id"] not in cc_references:
                continue
            ids.append(cert["_id"])
            component = cc_references[cert["_id"]]
            if id(component) not in components:
                components[id(component)] = component
        return network_graph_func(list(components.values()), highlighted=ids)
    else:
        components = {}
        for component in cc_references.values():
            if id(component) not in components:
                components[id(component)] = component
        return network_graph_func(list(components.values()))


@cc.route("/data/")
def data():
    last_ok_run = mongo.db.cc_log.find_one({"ok": True}, sort=[("start_time", pymongo.DESCENDING)])
    return render_template("cc/data.html.jinja2", last_ok_run=last_ok_run)


@cc.route("/search/")
@register_breadcrumb(cc, ".search", "Search")
def search():
    args = {**request.args, "searchType": "by-name"}
    return redirect(url_for(".merged_search", **args))


@cc.route("/mergedsearch/")
@register_breadcrumb(cc, ".merged_search", "Search")
def merged_search():
    search_type = request.args.get("searchType")
    if search_type != "by-name" and search_type != "fulltext":
        search_type = "by-name"

    res = {}
    template = "cc/search/name_search.html.jinja2"
    if search_type == "by-name":
        res = CCBasicSearch.process_search(request)
    elif search_type == "fulltext":
        res = CCFulltextSearch.process_search(request)
        template = "cc/search/fulltext_search.html.jinja2"
    return render_template(
        template,
        **res,
        schemes=cc_schemes,
        title=f"Common Criteria [{res['q'] if res['q'] else ''}] ({res['page']}) | sec-certs.org",
        search_type=search_type,
    )


@cc.route("/ftsearch/")
@register_breadcrumb(cc, ".fulltext_search", "Fulltext search")
def fulltext_search():
    args = {**request.args, "searchType": "fulltext"}
    return redirect(url_for(".merged_search", **args))


@cc.route("/compare/<string(length=16):one_hashid>/<string(length=16):other_hashid>/")
def compare(one_hashid: str, other_hashid: str):
    with sentry_sdk.start_span(op="mongo", description="Find certs"):
        raw_one = mongo.db.cc.find_one({"_id": one_hashid}, {"_id": 0})
        raw_other = mongo.db.cc.find_one({"_id": other_hashid}, {"_id": 0})
    if not raw_one or not raw_other:
        return abort(404)
    doc_one = load(raw_one)
    doc_other = load(raw_other)
    return render_template(
        "common/compare.html.jinja2",
        changes=render_compare(doc_one, doc_other, cc_diff_method),
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
    return render_template("cc/analysis.html.jinja2")


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
        return redirect(redir_path, code=301)
    else:
        return abort(404)


def redir_new(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        hashid = request.view_args.get("hashid")
        if hashid:
            new = mongo.db.cc_old.find_one({"_id": hashid}, {"hashid": 1})
            if new:
                new_args = request.view_args.copy()
                new_args["hashid"] = new["hashid"]
                return redirect(url_for(request.endpoint, **new_args), code=301)
        return func(*args, **kwargs)

    return wrapper


@cc.route("/<string(length=16):hashid>/")
@register_breadcrumb(
    cc, ".entry", "", dynamic_list_constructor=lambda *a, **kw: [{"text": request.view_args["hashid"]}]  # type: ignore
)
@redir_new
def entry(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        raw_doc = mongo.db.cc.find_one({"_id": hashid}, {"_id": 0})
    if raw_doc:
        doc = load(raw_doc)
        with sentry_sdk.start_span(op="mongo", description="Find profiles"):
            profiles = {}
            if "protection_profiles" in doc["heuristics"] and doc["heuristics"]["protection_profiles"]:
                res = mongo.db.pp.find({"_id": {"$in": list(doc["heuristics"]["protection_profiles"])}})
                profiles = {p["_id"]: load(p) for p in res}
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
            cc_map = get_cc_references()
            cert_network = cc_map.get(hashid, {})
        with sentry_sdk.start_span(op="mongo", description="Find prev/next certificates"):
            # No need to "load()" the certs as they have no non-trivial types.
            if "prev_certificates" in doc["heuristics"] and doc["heuristics"]["prev_certificates"]:
                previous = list(
                    mongo.db.cc.find(
                        {"heuristics.cert_id": {"$in": list(doc["heuristics"]["prev_certificates"])}},
                        {"_id": 1, "name": 1, "dgst": 1, "heuristics.cert_id": 1, "not_valid_before": 1},
                    ).sort([("not_valid_before._value", pymongo.ASCENDING)])
                )
            else:
                previous = []
            if "next_certificates" in doc["heuristics"] and doc["heuristics"]["next_certificates"]:
                next = list(
                    mongo.db.cc.find(
                        {"heuristics.cert_id": {"$in": list(doc["heuristics"]["next_certificates"])}},
                        {"_id": 1, "name": 1, "dgst": 1, "heuristics.cert_id": 1, "not_valid_before": 1},
                    ).sort([("not_valid_before._value", pymongo.ASCENDING)])
                )
            else:
                next = []
        with sentry_sdk.start_span(op="mongo", description="Find subscription"):
            if current_user.is_authenticated:
                subs = mongo.db.subs.find_one(
                    {"username": current_user.username, "type": "changes", "certificate.hashid": hashid}
                )
                subscribed = subs["updates"] if subs else None
            else:
                subscribed = None
        with sentry_sdk.start_span(op="mongo", description="Find related certificates"):
            # No need to "load()" the certs as they have no non-trivial types.
            similar_projection = {
                "_id": 1,
                "name": 1,
                "dgst": 1,
                "heuristics.cert_id": 1,
                "state.cert.pdf_hash": 1,
                "state.report.pdf_hash": 1,
                "state.st.pdf_hash": 1,
            }
            exact_queries = []
            if doc["name"]:
                exact_queries.append({"name": doc["name"]})
            if doc["heuristics"]["cert_id"]:
                exact_queries.append({"heuristics.cert_id": doc["heuristics"]["cert_id"]})
            exact = list(mongo.db.cc.find({"$or": exact_queries}, similar_projection)) if exact_queries else []
            doc_hash_queries = []
            for doctype in ("cert", "report", "st"):
                if doc["state"][doctype]["pdf_hash"]:
                    doc_hash_queries.append({f"state.{doctype}.pdf_hash": doc["state"][doctype]["pdf_hash"]})
            doc_hash_match = (
                list(mongo.db.cc.find({"$or": doc_hash_queries}, similar_projection)) if doc_hash_queries else []
            )
            related = (
                list(
                    filter(
                        lambda cert: cert["score"] > 4,
                        mongo.db.cc.find(
                            {"$text": {"$search": doc["name"]}},
                            {"score": {"$meta": "textScore"}, **similar_projection},
                            sort=[("score", {"$meta": "textScore"})],
                        ),
                    )
                )
                if doc["name"]
                else []
            )
            similar = list(
                {
                    cert["dgst"]: cert for cert in exact + doc_hash_match + related if cert["dgst"] != doc["dgst"]
                }.values()
            )
            same = []
            for other in similar:
                score = 0
                if (name := doc["name"]) and other["name"] == name:
                    score += 1
                if (cert_id := doc["heuristics"]["cert_id"]) and other["heuristics"]["cert_id"] == cert_id:
                    score += 1
                for doctype in ("cert", "report", "st"):
                    if (pdf_hash := doc["state"][doctype]["pdf_hash"]) and other["state"][doctype][
                        "pdf_hash"
                    ] == pdf_hash:
                        score += 1
                if score >= 2:
                    same.append(other)
        name = doc["name"] if doc["name"] else ""
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
            title=f"{name} | sec-certs.org",
            similar=similar,
            previous=previous,
            next=next,
            same=same,
            removed=diffs[0]["type"] == "remove",
            subscribed=subscribed,
        )
    else:
        return abort(404)


@cc.route("/<string(length=16):hashid>/target.txt")
@redir_new
@expires_at(cron("0 12 * * 2"))
def entry_target_txt(hashid):
    return entry_download_target_txt("cc", hashid, current_app.config["DATASET_PATH_CC_DIR"])


@cc.route("/<string(length=16):hashid>/target.pdf")
@redir_new
@expires_at(cron("0 12 * * 2"))
def entry_target_pdf(hashid):
    return entry_download_target_pdf("cc", hashid, current_app.config["DATASET_PATH_CC_DIR"])


@cc.route("/<string(length=16):hashid>/report.txt")
@redir_new
@expires_at(cron("0 12 * * 2"))
def entry_report_txt(hashid):
    return entry_download_report_txt("cc", hashid, current_app.config["DATASET_PATH_CC_DIR"])


@cc.route("/<string(length=16):hashid>/report.pdf")
@redir_new
@expires_at(cron("0 12 * * 2"))
def entry_report_pdf(hashid):
    return entry_download_report_pdf("cc", hashid, current_app.config["DATASET_PATH_CC_DIR"])


@cc.route("/<string(length=16):hashid>/cert.txt")
@redir_new
@expires_at(cron("0 12 * * 2"))
def entry_cert_txt(hashid):
    return entry_download_certificate_txt("cc", hashid, current_app.config["DATASET_PATH_CC_DIR"])


@cc.route("/<string(length=16):hashid>/cert.pdf")
@redir_new
@expires_at(cron("0 12 * * 2"))
def entry_cert_pdf(hashid):
    return entry_download_certificate_pdf("cc", hashid, current_app.config["DATASET_PATH_CC_DIR"])


@cc.route("/<string(length=16):hashid>/graph.json")
@redir_new
def entry_graph_json(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        doc = mongo.db.cc.find_one({"_id": hashid}, {"_id": 1})
    if doc:
        cc_map = get_cc_references()
        if hashid in cc_map.keys():
            network_data = node_link_data(cc_map[hashid], edges="links")
        else:
            network_data = {}
        network_data["highlighted"] = [hashid]
        return send_json_attachment(network_data)
    else:
        return abort(404)


@cc.route("/<string(length=16):hashid>/cert.json")
@redir_new
def entry_json(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        doc = mongo.db.cc.find_one({"_id": hashid})
    if doc:
        return send_json_attachment(StorageFormat(doc).to_json_mapping())
    else:
        return abort(404)


@cc.route("/<string(length=16):hashid>/feed.xml")
@redir_new
def entry_feed(hashid):
    feed = Feed(
        CCRenderer(), "img/cc_card.png", mongo.db.cc, mongo.db.cc_diff, lambda doc: doc["name"] if doc["name"] else ""
    )
    response = feed.render(hashid)
    if response:
        return response
    else:
        return abort(404)


@cc.route("/id/<path:cert_id>")
def entry_id(cert_id):
    with sentry_sdk.start_span(op="mongo", description="Find certs"):
        ids = list(mongo.db.cc.find({"heuristics.cert_id": cert_id}, {"_id": 1}))
    if ids:
        if len(ids) == 1:
            return redirect(url_for("cc.entry", hashid=ids[0]["_id"]))
        else:
            docs = list(map(load, mongo.db.cc.find({"_id": {"$in": list(map(itemgetter("_id"), ids))}})))
            return render_template(
                "cc/entry/disambiguate.html.jinja2", certs=docs, attr_value=cert_id, attr_name="certificate ID"
            )
    else:
        return abort(404)


@cc.route("/name/<path:name>")
def entry_name(name):
    with sentry_sdk.start_span(op="mongo", description="Find certs"):
        ids = list(mongo.db.cc.find({"name": name}, {"_id": 1}))
    if ids:
        if len(ids) == 1:
            return redirect(url_for("cc.entry", hashid=ids[0]["_id"]))
        else:
            docs = list(map(load, mongo.db.cc.find({"_id": {"$in": list(map(itemgetter("_id"), ids))}})))
            return render_template("cc/entry/disambiguate.html.jinja2", certs=docs, attr_value=name, attr_name="name")
    else:
        return abort(404)


@sitemap.register_generator
def sitemap_urls():
    yield "cc.index", {}, None, None, 0.9
    yield "cc.dataset", {}
    yield "cc.maintenance_updates", {}
    yield "cc.network", {}
    yield "cc.analysis", {}
    yield "cc.search", {}
    yield "cc.fulltext_search", {}
    yield "cc.rand", {}
    for doc in mongo.db.cc.aggregate(sitemap_cert_pipeline("cc"), allowDiskUse=True):
        yield "cc.entry", {"hashid": doc["_id"]}, doc["timestamp"].strftime("%Y-%m-%d"), "weekly", 0.8
