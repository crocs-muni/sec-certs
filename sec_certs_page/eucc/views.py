"""EUCC views."""

import random
from operator import itemgetter

import sentry_sdk
from flask import render_template, request, redirect, url_for, abort
from werkzeug.utils import safe_join

from . import eucc, eucc_schemes
from .tasks import EUCCRenderer
from .. import mongo
from ..cc import redir_new, get_cc_references
from .search import EUCCBasicSearch, EUCCFulltextSearch
from ..common.diffs import render_compare, eucc_diff_method
from ..common.feed import Feed
from ..common.views import (
    register_breadcrumb, expires_at, entry_download_certificate_pdf, entry_download_certificate_txt,
    entry_download_report_pdf, entry_download_report_txt, entry_download_target_pdf, entry_download_target_txt,
    entry_download_files, send_cacheable_instance_file, send_json_attachment,
)
from ..common.objformats import StorageFormat, load
import pymongo
from flask import current_app
from flask_login import current_user
from periodiq import cron


@eucc.route("/")
@register_breadcrumb(eucc, ".", "EUCC")
def index():
    """EUCC index."""
    return render_template("eucc/index.html.jinja2")


@eucc.route("/dataset.json")
def dataset():
    """EUCC dataset API endpoint."""
    return send_cacheable_instance_file(current_app.config["DATASET_PATH_EUCC_OUT"], "application/json", "dataset.json")


@eucc.route("/eucc.tar.gz")
def dataset_archive():
    """EUCC dataset archive API endpoint."""
    return send_cacheable_instance_file(current_app.config["DATASET_PATH_EUCC_ARCHIVE"], "application/gzip",
                                        "eucc.tar.gz")


@eucc.route("/schemes.json")
def schemes():
    """EUCC scheme dataset API endpoint."""
    return send_cacheable_instance_file(
        current_app.config["DATASET_PATH_EUCC_OUT_SCHEME"], "application/json", "schemes.json"
    )

@eucc.route("/network/")
@register_breadcrumb(eucc, ".network", "References")
def network():
    """EUCC references visualization."""
    # TODO Not implemented yet, not many certificates

@eucc.route("/data/")
def data():
    last_ok_run = mongo.db.eucc_log.find_one({"ok": True}, sort=[("start_time", pymongo.DESCENDING)])
    return render_template("eucc/data.html.jinja2", last_ok_run=last_ok_run)


@eucc.route("/search/")
@register_breadcrumb(eucc, ".search", "Search")
def search():
    args = {**request.args, "searchType": "by-name"}
    return redirect(url_for(".merged_search", **args))


@eucc.route("/mergedsearch/")
@register_breadcrumb(eucc, ".merged_search", "Search")
def merged_search():
    search_type = request.args.get("searchType")
    if search_type != "by-name" and search_type != "fulltext":
        search_type = "by-name"

    res = {}
    template = "eucc/search/name_search.html.jinja2"
    if search_type == "by-name":
        res = EUCCBasicSearch.process_search(request)
    elif search_type == "fulltext":
        res = EUCCFulltextSearch.process_search(request)
        template = "eucc/search/fulltext_search.html.jinja2"
    return render_template(
        template,
        **res,
        schemes=eucc_schemes,
        title=f"EUCC [{res['q'] if res['q'] else ''}] ({res['page']}) | sec-certs.org",
        search_type=search_type,
    )


@eucc.route("/ftsearch/")
@register_breadcrumb(eucc, ".fulltext_search", "Fulltext search")
def fulltext_search():
    args = {**request.args, "searchType": "fulltext"}
    return redirect(url_for(".merged_search", **args))


@eucc.route("/compare/<string(length=16):one_hashid>/<string(length=16):other_hashid>/")
def compare(one_hashid: str, other_hashid: str):
    with sentry_sdk.start_span(op="mongo", description="Find certs"):
        raw_one = mongo.db.eucc.find_one({"_id": one_hashid}, {"_id": 0})
        raw_other = mongo.db.eucc.find_one({"_id": other_hashid}, {"_id": 0})
    if not raw_one or not raw_other:
        return abort(404)
    doc_one = load(raw_one)
    doc_other = load(raw_other)
    return render_template(
        "common/compare.html.jinja2",
        changes=render_compare(doc_one, doc_other, eucc_diff_method),
        cert_one=doc_one,
        cert_other=doc_other,
        name_one=doc_one["name"],
        name_other=doc_other["name"],
        hashid_one=one_hashid,
        hashid_other=other_hashid,
    )

@eucc.route("/random/")
def rand():
    """EUCC random certificate."""
    current_ids = list(map(itemgetter("_id"), mongo.db.eucc.find({}, ["_id"])))
    return redirect(url_for(".entry", hashid=random.choice(current_ids)))

@eucc.route("/<string(length=20):old_id>/")
@eucc.route("/<string(length=20):old_id>/<path:npath>")
def entry_old(old_id, npath=None):
    with sentry_sdk.start_span(op="mongo", description="Find id map entry."):
        id_map = mongo.db.eucc_old.find_one({"_id": old_id})
    if id_map:
        redir_path = url_for("eucc.entry", hashid=id_map["hashid"])
        if npath:
            redir_path = safe_join(redir_path, npath)
        return redirect(redir_path, code=301)
    else:
        return abort(404)

@eucc.route("/<string(length=16):hashid>/")
@register_breadcrumb(
    eucc, ".entry", "", dynamic_list_constructor=lambda *a, **kw: [{"text": request.view_args["hashid"]}]
    # type: ignore
)
@redir_new
def entry(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        raw_doc = mongo.db.eucc.find_one({"_id": hashid}, {"_id": 0})
    if raw_doc:
        doc = load(raw_doc)
        with sentry_sdk.start_span(op="mongo", description="Find profiles"):
            profiles = {}
            if "protection_profiles" in doc["heuristics"] and doc["heuristics"]["protection_profiles"]:
                res = mongo.db.pp.find({"_id": {"$in": list(doc["heuristics"]["protection_profiles"])}})
                profiles = {p["_id"]: load(p) for p in res}
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
            local_files = entry_download_files(hashid, current_app.config["DATASET_PATH_EUCC_DIR"])
        with sentry_sdk.start_span(op="network", description="Find network"):
            eucc_map = get_cc_references()
            cert_network = eucc_map.get(hashid, {})
        with sentry_sdk.start_span(op="mongo", description="Find prev/next certificates"):
            # No need to "load()" the certs as they have no non-trivial types.
            if "prev_certificates" in doc["heuristics"] and doc["heuristics"]["prev_certificates"]:
                previous = list(
                    mongo.db.eucc.find(
                        {"cert_id": {"$in": list(doc["heuristics"]["prev_certificates"])}},
                        {"_id": 1, "name": 1, "dgst": 1, "cert_id": 1, "not_valid_before": 1},
                    ).sort([("not_valid_before._value", pymongo.ASCENDING)])
                )
            else:
                previous = []
            if "next_certificates" in doc["heuristics"] and doc["heuristics"]["next_certificates"]:
                next = list(
                    mongo.db.eucc.find(
                        {"cert_id": {"$in": list(doc["heuristics"]["next_certificates"])}},
                        {"_id": 1, "name": 1, "dgst": 1, "cert_id": 1, "not_valid_before": 1},
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
                "cert_id": 1,
                "state.cert.pdf_hash": 1,
                "state.report.pdf_hash": 1,
                "state.st.pdf_hash": 1,
            }
            exact_queries = []
            if doc["name"]:
                exact_queries.append({"name": doc["name"]})
            if doc["cert_id"]:
                exact_queries.append({"cert_id": doc["cert_id"]})
            exact = list(mongo.db.eucc.find({"$or": exact_queries}, similar_projection)) if exact_queries else []
            doc_hash_queries = []
            for doctype in ("cert", "report", "st"):
                if doc["state"][doctype]["pdf_hash"]:
                    doc_hash_queries.append({f"state.{doctype}.pdf_hash": doc["state"][doctype]["pdf_hash"]})
            doc_hash_match = (
                list(mongo.db.eucc.find({"$or": doc_hash_queries}, similar_projection)) if doc_hash_queries else []
            )
            related = (
                list(
                    filter(
                        lambda cert: cert["score"] > 4,
                        mongo.db.eucc.find(
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
                if (cert_id := doc["cert_id"]) and other["cert_id"] == cert_id:
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
            "eucc/entry/index.html.jinja2",
            cert=doc,
            hashid=hashid,
            profiles=profiles,
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
            subscribed=subscribed,
        )
    else:
        return abort(404)


@eucc.route("/<string(length=16):hashid>/target.txt")
@redir_new
@expires_at(cron("0 12 * * 2"))
def entry_target_txt(hashid):
    return entry_download_target_txt("eucc", hashid, current_app.config["DATASET_PATH_CC_DIR"])


@eucc.route("/<string(length=16):hashid>/target.pdf")
@redir_new
@expires_at(cron("0 12 * * 2"))
def entry_target_pdf(hashid):
    return entry_download_target_pdf("eucc", hashid, current_app.config["DATASET_PATH_EUCC_DIR"])


@eucc.route("/<string(length=16):hashid>/report.txt")
@redir_new
@expires_at(cron("0 12 * * 2"))
def entry_report_txt(hashid):
    return entry_download_report_txt("eucc", hashid, current_app.config["DATASET_PATH_EUCC_DIR"])


@eucc.route("/<string(length=16):hashid>/report.pdf")
@redir_new
@expires_at(cron("0 12 * * 2"))
def entry_report_pdf(hashid):
    return entry_download_report_pdf("eucc", hashid, current_app.config["DATASET_PATH_EUCC_DIR"])


@eucc.route("/<string(length=16):hashid>/cert.txt")
@redir_new
@expires_at(cron("0 12 * * 2"))
def entry_cert_txt(hashid):
    return entry_download_certificate_txt("eucc", hashid, current_app.config["DATASET_PATH_EUCC_DIR"])


@eucc.route("/<string(length=16):hashid>/cert.pdf")
@redir_new
@expires_at(cron("0 12 * * 2"))
def entry_cert_pdf(hashid):
    return entry_download_certificate_pdf("eucc", hashid, current_app.config["DATASET_PATH_EUCC_DIR"])

@eucc.route("/<string(length=16):hashid>/cert.json")
@redir_new
def entry_json(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        doc = mongo.db.eucc.find_one({"_id": hashid})
    if doc:
        return send_json_attachment(StorageFormat(doc).to_json_mapping())
    else:
        return abort(404)


@eucc.route("/<string(length=16):hashid>/feed.xml")
@redir_new
def entry_feed(hashid):
    feed = Feed(
        EUCCRenderer(), "img/eucc_card.png", mongo.db.eucc, mongo.db.eucc_diff, lambda doc: doc["name"] if doc["name"] else ""
    )
    response = feed.render(hashid)
    if response:
        return response
    else:
        return abort(404)

@eucc.route("/id/<path:cert_id>")
def entry_id(cert_id):
    with sentry_sdk.start_span(op="mongo", description="Find certs"):
        ids = list(mongo.db.eucc.find({"cert_id": cert_id}, {"_id": 1}))
    if ids:
        if len(ids) == 1:
            return redirect(url_for("eucc.entry", hashid=ids[0]["_id"]))
        else:
            docs = list(map(load, mongo.db.eucc.find({"_id": {"$in": list(map(itemgetter("_id"), ids))}})))
            return render_template(
                "eucc/entry/disambiguate.html.jinja2", certs=docs, attr_value=cert_id, attr_name="certificate ID"
            )
    else:
        return abort(404)


@eucc.route("/name/<path:name>")
def entry_name(name):
    with sentry_sdk.start_span(op="mongo", description="Find certs"):
        ids = list(mongo.db.eucc.find({"name": name}, {"_id": 1}))
    if ids:
        if len(ids) == 1:
            return redirect(url_for("cc.entry", hashid=ids[0]["_id"]))
        else:
            docs = list(map(load, mongo.db.eucc.find({"_id": {"$in": list(map(itemgetter("_id"), ids))}})))
            return render_template("eucc/entry/disambiguate.html.jinja2", certs=docs, attr_value=name, attr_name="name")
    else:
        return abort(404)
