import random
from operator import itemgetter
from pathlib import Path

import pymongo
import sentry_sdk
from flask import abort, current_app, redirect, render_template, request, send_file, url_for
from flask_breadcrumbs import register_breadcrumb

from .. import mongo, sitemap
from ..cc import cc_schemes
from ..common.feed import Feed
from ..common.objformats import StorageFormat, load
from ..common.views import (
    entry_download_files,
    entry_download_profile_pdf,
    entry_download_profile_txt,
    entry_download_report_pdf,
    entry_download_report_txt,
    send_json_attachment,
)
from . import pp
from .search import PPBasicSearch, PPFulltextSearch
from .tasks import PPRenderer


@pp.route("/")
@register_breadcrumb(pp, ".", "Protection Profiles")
def index():
    last_ok_run = mongo.db.pp_log.find_one({"ok": True}, sort=[("start_time", pymongo.DESCENDING)])
    return render_template("pp/index.html.jinja2", last_ok_run=last_ok_run)


@pp.route("/network/")
@register_breadcrumb(pp, ".network", "References")
def network():
    return render_template("pp/network.html.jinja2")


@pp.route("/data")
def data():
    return render_template("pp/data.html.jinja2")

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


@pp.route("/pp.tar.gz")
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

@pp.route("/mergedsearch/")
def mergedSearch():
    searchType = request.args.get("searchType")
    if(searchType != "byName" and searchType != "fulltext"):
        searchType = "byName"

    res = {}
    if(searchType == "byName"):
        res = PPBasicSearch.process_search(request)
    elif(searchType == "fulltext"):
        res = PPFulltextSearch.process_search(request)
    return render_template("cc/search/merged.html.jinja2", **res, schemes=cc_schemes, title="TODO:", searchType=searchType)

@pp.route("/search/")
@register_breadcrumb(pp, ".search", "Search")
def search():
    """Protection Profile search."""
    res = PPBasicSearch.process_search(request)
    return render_template(
        "pp/search/index.html.jinja2",
        **res,
        schemes=cc_schemes,
        title=f"Protection Profile [{res['q'] if res['q'] else ''}] ({res['page']}) | sec-certs.org",
    )


@pp.route("/search/pagination/")
def search_results():
    """Protection Profile search (raw results, pagination + timeline)."""

    def callback(**kwargs):
        return url_for(".search", **kwargs)

    res = PPBasicSearch.process_search(request, callback=callback)
    return render_template("pp/search/results.html.jinja2", **res)


@pp.route("/ftsearch/")
@register_breadcrumb(pp, ".fulltext_search", "Fulltext search")
def fulltext_search():
    """Fulltext search for Protection Profiles."""
    res = PPFulltextSearch.process_search(request)
    return render_template(
        "pp/search/fulltext.html.jinja2",
        **res,
        schemes=cc_schemes,
        title=f"Protection Profile [{res['q'] if res['q'] else ''}] ({res['page']}) | sec-certs.org",
    )


@pp.route("/<string(length=16):hashid>/")
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
        renderer = PPRenderer()
        with sentry_sdk.start_span(op="mongo", description="Find and render diffs"):
            diffs = list(mongo.db.pp_diff.find({"dgst": hashid}, sort=[("timestamp", pymongo.DESCENDING)]))
            diff_jsons = list(map(lambda x: StorageFormat(x).to_json_mapping(), diffs))
            diffs = list(map(load, diffs))
            diff_renders = list(map(lambda x: renderer.render_diff(hashid, doc, x, linkback=False), diffs))
        with sentry_sdk.start_span(op="files", description="Find local files"):
            local_files = entry_download_files(hashid, current_app.config["DATASET_PATH_PP_DIR"])
        name = doc["web_data"]["name"] if doc["web_data"] and doc["web_data"]["name"] else ""
        return render_template(
            "pp/entry/index.html.jinja2",
            profile=doc,
            hashid=hashid,
            certs=certs,
            diffs=diffs,
            diff_jsons=diff_jsons,
            diff_renders=diff_renders,
            local_files=local_files,
            title=f"{name} | sec-certs.org",
            json=StorageFormat(raw_doc).to_json_mapping(),
        )
    else:
        return abort(404)


@pp.route("/<string(length=16):hashid>/report.txt")
def entry_report_txt(hashid):
    return entry_download_report_txt("pp", hashid, current_app.config["DATASET_PATH_PP_DIR"])


@pp.route("/<string(length=16):hashid>/report.pdf")
def entry_report_pdf(hashid):
    return entry_download_report_pdf("pp", hashid, current_app.config["DATASET_PATH_PP_DIR"])


@pp.route("/<string(length=16):hashid>/profile.txt")
def entry_profile_txt(hashid):
    return entry_download_profile_txt("pp", hashid, current_app.config["DATASET_PATH_PP_DIR"])


@pp.route("/<string(length=16):hashid>/profile.pdf")
def entry_profile_pdf(hashid):
    return entry_download_profile_pdf("pp", hashid, current_app.config["DATASET_PATH_PP_DIR"])


@pp.route("/<string(length=16):hashid>/profile.json")
def entry_json(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find profile"):
        doc = mongo.db.pp.find_one({"_id": hashid})
    if doc:
        return send_json_attachment(StorageFormat(doc).to_json_mapping())
    else:
        return abort(404)


@pp.route("/<string(length=16):hashid>/feed.xml")
def entry_feed(hashid):
    feed = Feed(
        PPRenderer(),
        "img/pp_card.png",
        mongo.db.pp,
        mongo.db.pp_diff,
        lambda doc: doc["web_data"]["name"] if doc["web_data"]["name"] else "",
    )
    response = feed.render(hashid)
    if response:
        return response
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
            return render_template("pp/entry/disambiguate.html.jinja2", pps=docs, name=name)
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
        yield "pp.entry", {"hashid": doc["_id"]}, None, None, 0.8
