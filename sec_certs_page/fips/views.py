"""FIPS views."""
import operator
import random
import time
from datetime import datetime
from functools import reduce
from operator import itemgetter
from pathlib import Path

import pymongo
import sentry_sdk
from feedgen.feed import FeedGenerator
from flask import Response, abort, current_app, redirect, render_template, request, send_file, url_for
from flask_breadcrumbs import register_breadcrumb
from flask_cachecontrol import cache_for
from networkx import node_link_data
from pytz import timezone
from sec_certs import constants
from werkzeug.exceptions import BadRequest
from werkzeug.utils import safe_join
from whoosh import highlight
from whoosh.qparser import QueryParser, query

from .. import cache, get_searcher, mongo, sitemap
from ..common.objformats import StorageFormat, load
from ..common.search import index_schema
from ..common.views import (
    Pagination,
    entry_download_files,
    entry_download_target_pdf,
    entry_download_target_txt,
    entry_file_path,
    network_graph_func,
    send_json_attachment,
)
from . import fips, fips_reference_types, fips_status, fips_types, get_fips_graphs, get_fips_map
from .tasks import FIPSRenderer


@fips.app_template_global("get_fips_type")
def get_fips_type(name):
    return fips_types.get(name, None)


@fips.route("/types.json")
@cache.cached(60 * 60)
@cache_for(days=7)
def types():
    return send_json_attachment(fips_types)


@fips.route("/status.json")
@cache.cached(60 * 60)
@cache_for(days=7)
def statuses():
    return send_json_attachment(fips_status)


@fips.route("/reference_types.json")
@cache.cached(60 * 60)
@cache_for(days=7)
def reference_types():
    return send_json_attachment(fips_reference_types)


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
        download_name="dataset.json",
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
@cache_for(hours=12)
def network_graph():
    return network_graph_func(get_fips_graphs())


def select_certs(q, cat, status, sort):
    categories = fips_types.copy()
    query = {}
    projection = {
        "_id": 1,
        "cert_id": 1,
        "web_data.module_name": 1,
        "web_data.status": 1,
        "web_data.level": 1,
        "web_data.vendor": 1,
        "web_data.module_type": 1,
        "web_data.validation_history": 1,
        "web_data.date_sunset": 1,
    }

    if q is not None and q != "":
        projection["score"] = {"$meta": "textScore"}
        try:
            iq = int(q)
            query["$or"] = [{"$text": {"$search": q}}, {"cert_id": iq}]
        except ValueError:
            query["$text"] = {"$search": q}

    if cat is not None:
        selected_cats = []
        for name, category in categories.items():
            if category["id"] in cat:
                selected_cats.append(name)
                category["selected"] = True
            else:
                category["selected"] = False
        query["web_data.module_type"] = {"$in": selected_cats}
    else:
        for category in categories.values():
            category["selected"] = True

    if status is not None and status != "Any":
        query["web_data.status"] = status

    with sentry_sdk.start_span(op="mongo", description="Find certs."):
        cursor = mongo.db.fips.find(query, projection)
        count = mongo.db.fips.count_documents(query)

    if sort == "match" and q is not None and q != "":
        cursor.sort(
            [
                ("score", {"$meta": "textScore"}),
                ("web_data.module_name", pymongo.ASCENDING),
            ]
        )
    elif sort == "number":
        cursor.sort([("cert_id", pymongo.ASCENDING)])
    elif sort == "first_cert_date":
        cursor.sort([("web_data.validation_history.0.date._value", pymongo.ASCENDING)])
    elif sort == "last_cert_date":
        cursor.sort([("web_data.validation_history", pymongo.ASCENDING)])
    elif sort == "sunset_date":
        cursor.sort([("web_data.date_sunset", pymongo.ASCENDING)])
    elif sort == "level":
        cursor.sort([("web_data.level", pymongo.ASCENDING)])
    elif sort == "vendor":
        cursor.sort([("web_data.vendor", pymongo.ASCENDING)])
    else:
        cursor.sort([("cert_id", pymongo.ASCENDING)])
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
        "fips/search/index.html.jinja2",
        **res,
        title=f"FIPS 140 [{res['q']}] ({res['page']}) | seccerts.org",
    )


@fips.route("/ftsearch/")
@register_breadcrumb(fips, ".fulltext_search", "Fulltext search")
def fulltext_search():
    categories = fips_types.copy()
    try:
        page = int(request.args.get("page", 1))
    except ValueError:
        raise BadRequest(description="Invalid page number.")
    q = request.args.get("q", None)
    cat = request.args.get("cat", None)
    q_filter = query.Term("cert_schema", "fips")
    if cat is not None:
        cat_terms = []
        for name, category in categories.items():
            if category["id"] in cat:
                cat_terms.append(query.Term("category", category["id"]))
                category["selected"] = True
            else:
                category["selected"] = False
        q_filter &= reduce(operator.or_, cat_terms)
    else:
        for category in categories.values():
            category["selected"] = True

    type = request.args.get("type", "any")
    if type not in ("any", "report", "target"):
        raise BadRequest(description="Invalid type.")
    if type != "any":
        q_filter &= query.Term("document_type", type)

    status = request.args.get("status", "Any")
    if status not in ("Any", "Active", "Historical", "Revoked"):
        raise BadRequest(description="Invalid status.")
    if status != "Any":
        q_filter &= query.Term("status", status)

    if q is None:
        return render_template(
            "fips/search/fulltext.html.jinja2",
            categories=categories,
            status=status,
            document_type=type,
            results=[],
            pagination=None,
            q=q,
        )

    per_page = current_app.config["SEARCH_ITEMS_PER_PAGE"]

    parser = QueryParser("content", schema=index_schema)
    qr = parser.parse(q)
    results = []
    with sentry_sdk.start_span(op="whoosh.get_searcher", description="Get whoosh searcher"):
        searcher = get_searcher()
    with sentry_sdk.start_span(op="whoosh.search", description="Search"):
        res = searcher.search_page(qr, pagenum=page, filter=q_filter, pagelen=per_page)
    res.results.fragmenter.charlimit = None
    res.results.fragmenter.maxchars = 300
    res.results.fragmenter.surround = 40
    res.results.order = highlight.SCORE
    hf = highlight.HtmlFormatter(between="<br/>")
    res.results.formatter = hf
    runtime = res.results.runtime
    # print("total", res.total)
    # print("len", len(res))
    # print("scored", res.scored_length())
    # print("filtered", res.results.filtered_count)
    count = len(res)
    highlite_start = time.perf_counter()
    with sentry_sdk.start_span(op="whoosh.highlight", description="Highlight results"):
        for hit in res:
            dgst = hit["dgst"]
            cert = mongo.db.fips.find_one({"_id": dgst})
            entry = {"hit": hit, "cert": cert}
            fpath = entry_file_path(dgst, current_app.config["DATASET_PATH_FIPS_DIR"], hit["document_type"], "txt")
            try:
                with open(fpath) as f:
                    contents = f.read()
                hlt = hit.highlights("content", text=contents)
                entry["highlights"] = hlt
            except FileNotFoundError:
                pass
            results.append(entry)
    highlite_runtime = time.perf_counter() - highlite_start

    pagination = Pagination(
        page=page,
        per_page=per_page,
        search=True,
        found=count,
        total=mongo.db.fips.count_documents({}),
        css_framework="bootstrap5",
        alignment="center",
    )
    return render_template(
        "fips/search/fulltext.html.jinja2",
        q=q,
        results=results,
        categories=categories,
        status=status,
        pagination=pagination,
        document_type=type,
        runtime=runtime,
        highlite_runtime=highlite_runtime,
    )


@fips.route("/search/pagination/")
def search_pagination():
    def callback(**kwargs):
        return url_for(".search", **kwargs)

    res = process_search(request, callback=callback)
    return render_template("fips/search/pagination.html.jinja2", **res)


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
        mongo.db.fips_mip.find({}).sort([("timestamp", pymongo.DESCENDING)]).skip((page - 1) * per_page).limit(per_page)
    )
    count = mongo.db.fips_mip.count_documents({})

    pagination = Pagination(
        page=page,
        per_page=per_page,
        search=False,
        found=len(mip_snapshots),
        total=count,
        css_framework="bootstrap5",
        alignment="center",
    )
    return render_template("fips/mip/mip_index.html.jinja2", snapshots=mip_snapshots, pagination=pagination)


@fips.route("/mip/dataset.json")
def mip_dataset():
    # TODO: Make this go through the proper deserialization path.
    mip_snapshots = list(mongo.db.fips_mip.find({}, {"_id": 0}).sort([("timestamp", pymongo.DESCENDING)]))
    return send_json_attachment(
        {
            "_type": "sec_certs.dataset.fips_mip.MIPDataset",
            "snapshots": [StorageFormat(snapshot).to_json_mapping() for snapshot in mip_snapshots],
        }
    )


@fips.route("/mip/<ObjectId:id>")
@register_breadcrumb(
    fips,
    ".mip.snapshot",
    "",
    dynamic_list_constructor=lambda *args, **kwargs: [{"text": request.view_args["id"]}],  # type: ignore
)
def mip_snapshot(id):
    snapshot = mongo.db.fips_mip.find_one_or_404({"_id": id})
    return render_template("fips/mip/mip.html.jinja2", snapshot=snapshot)


@fips.route("/mip/<ObjectId:id>.json")
def mip_snapshot_json(id):
    snapshot = mongo.db.fips_mip.find_one_or_404({"_id": id}, {"_id": 0})
    return send_json_attachment(StorageFormat(snapshot).to_json_mapping())


@fips.route("/mip/latest.json")
def mip_snapshot_latest_json():
    snapshot = list(mongo.db.fips_mip.find({}, {"_id": 0}).sort([("timestamp", pymongo.DESCENDING)]).limit(1))[0]
    return send_json_attachment(StorageFormat(snapshot).to_json_mapping())


@fips.route("/mip/entry/<path:name>")
@register_breadcrumb(
    fips,
    ".mip.entry",
    "",
    dynamic_list_constructor=lambda *args, **kwargs: [{"text": request.view_args["name"]}],  # type: ignore
)
def mip_entry(name):
    snapshots = list(mongo.db.fips_mip.find({"entries.module_name": name}).sort([("timestamp", pymongo.ASCENDING)]))
    if not snapshots:
        return abort(404)
    first_present = datetime.fromisoformat(snapshots[0]["timestamp"]).replace(hour=0, minute=0, second=0)
    last_present = datetime.fromisoformat(snapshots[-1]["timestamp"]).replace(hour=0, minute=0, second=0)
    state_changes = []
    for snap in snapshots:
        snap["entries"] = list(filter(lambda entry: entry["module_name"] == name, snap["entries"]))
        one_entry = snap["entries"][0]
        # TODO: More than one entry might be present, add a test?
        if not state_changes or state_changes[-1][1] != one_entry["status"]:
            change_date = datetime.fromisoformat(snap["timestamp"])
            state_changes.append([change_date, one_entry["status"]])
    for i, change in enumerate(state_changes):
        if i + 1 == len(state_changes):
            next_change = last_present
        else:
            next_change = state_changes[i + 1][0]
        change.append((next_change - change[0]).days)
    present = last_present - first_present
    return render_template(
        "fips/mip/mip_entry.html.jinja2", snapshots=snapshots, name=name, present=present, state_changes=state_changes
    )


@fips.route("/iut/")
@register_breadcrumb(fips, ".iut", "IUT")
def iut_index():
    try:
        page = int(request.args.get("page", 1))
    except ValueError:
        raise BadRequest(description="Invalid page number.")

    per_page = current_app.config["SEARCH_ITEMS_PER_PAGE"]
    iut_snapshots = list(
        mongo.db.fips_iut.find({}).sort([("timestamp", pymongo.DESCENDING)]).skip((page - 1) * per_page).limit(per_page)
    )
    count = mongo.db.fips_iut.count_documents({})

    pagination = Pagination(
        page=page,
        per_page=per_page,
        search=False,
        found=len(iut_snapshots),
        total=count,
        css_framework="bootstrap5",
        alignment="center",
    )
    return render_template("fips/iut/iut_index.html.jinja2", snapshots=iut_snapshots, pagination=pagination)


@fips.route("/iut/dataset.json")
def iut_dataset():
    # TODO: Make this go through the proper deserialization path.
    iut_snapshots = list(mongo.db.fips_iut.find({}, {"_id": 0}).sort([("timestamp", pymongo.DESCENDING)]))
    return send_json_attachment(
        {
            "_type": "sec_certs.dataset.fips_iut.IUTDataset",
            "snapshots": [StorageFormat(snapshot).to_json_mapping() for snapshot in iut_snapshots],
        }
    )


@fips.route("/iut/<ObjectId:id>")
@register_breadcrumb(
    fips,
    ".iut.snapshot",
    "",
    dynamic_list_constructor=lambda *args, **kwargs: [{"text": request.view_args["id"]}],  # type: ignore
)
def iut_snapshot(id):
    snapshot = mongo.db.fips_iut.find_one_or_404({"_id": id})
    return render_template("fips/iut/iut.html.jinja2", snapshot=snapshot)


@fips.route("/iut/<ObjectId:id>.json")
def iut_snapshot_json(id):
    snapshot = mongo.db.fips_iut.find_one_or_404({"_id": id}, {"_id": 0})
    return send_json_attachment(StorageFormat(snapshot).to_json_mapping())


@fips.route("/iut/latest.json")
def iut_snapshot_latest_json():
    snapshot = list(mongo.db.fips_iut.find({}, {"_id": 0}).sort([("timestamp", pymongo.DESCENDING)]).limit(1))[0]
    return send_json_attachment(StorageFormat(snapshot).to_json_mapping())


@fips.route("/iut/entry/<path:name>")
@register_breadcrumb(
    fips,
    ".iut.entry",
    "",
    dynamic_list_constructor=lambda *args, **kwargs: [{"text": request.view_args["name"]}],  # type: ignore
)
def iut_entry(name):
    snapshots = list(mongo.db.fips_iut.find({"entries.module_name": name}).sort([("timestamp", pymongo.ASCENDING)]))
    if not snapshots:
        return abort(404)
    for snap in snapshots:
        snap["entries"] = list(filter(lambda entry: entry["module_name"] == name, snap["entries"]))
    present = datetime.fromisoformat(snapshots[-1]["timestamp"]) - datetime.fromisoformat(snapshots[0]["timestamp"])
    return render_template("fips/iut/iut_entry.html.jinja2", snapshots=snapshots, name=name, present=present)


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
    dynamic_list_constructor=lambda *args, **kwargs: [{"text": request.view_args["hashid"]}],  # type: ignore
)
def entry(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        raw_doc = mongo.db.fips.find_one({"_id": hashid}, {"_id": 0})
    if raw_doc:
        doc = load(raw_doc)
        renderer = FIPSRenderer()
        with sentry_sdk.start_span(op="mongo", description="Find and render diffs"):
            diffs = list(mongo.db.fips_diff.find({"dgst": hashid}, sort=[("timestamp", pymongo.ASCENDING)]))
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
            local_files = entry_download_files(
                hashid, current_app.config["DATASET_PATH_FIPS_DIR"], documents=("target",)
            )
        return render_template(
            "fips/entry/index.html.jinja2",
            cert=doc,
            hashid=hashid,
            diffs=diffs,
            diff_jsons=diff_jsons,
            diff_renders=diff_renders,
            cves=cves,
            cpes=cpes,
            local_files=local_files,
            json=StorageFormat(raw_doc).to_json_mapping(),
            policy_link=constants.FIPS_SP_URL.format(doc["cert_id"]),
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
        network_data["highlighted"] = [hashid]
        return send_json_attachment(network_data)
    else:
        return abort(404)


@fips.route("/<string(length=16):hashid>/cert.json")
def entry_json(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        doc = mongo.db.fips.find_one({"_id": hashid}, {"_id": 0})
    if doc:
        return send_json_attachment(StorageFormat(doc).to_json_mapping())
    else:
        return abort(404)


@fips.route("/<string(length=16):hashid>/feed.xml")
def entry_feed(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        raw_doc = mongo.db.fips.find_one({"_id": hashid})
    if raw_doc:
        tz = timezone("Europe/Prague")
        doc = load(raw_doc)
        entry_url = url_for(".entry", hashid=hashid, _external=True)
        renderer = FIPSRenderer()
        with sentry_sdk.start_span(op="mongo", description="Find and render diffs"):
            diffs = list(map(load, mongo.db.fips_diff.find({"dgst": hashid}, sort=[("timestamp", pymongo.ASCENDING)])))
            diff_renders = list(map(lambda x: renderer.render_diff(hashid, doc, x, linkback=True), diffs))
        fg = FeedGenerator()
        fg.id(request.base_url)
        fg.title(doc["web_data"]["module_name"])
        fg.author({"name": "sec-certs", "email": "webmaster@seccerts.org"})
        fg.link({"href": entry_url, "rel": "alternate"})
        fg.link({"href": request.base_url, "rel": "self"})
        fg.icon(url_for("static", filename="img/favicon.png", _external=True))
        fg.logo(url_for("static", filename="img/fips_card.png", _external=True))
        fg.language("en")
        last_update = None
        for diff, render in zip(diffs, diff_renders):
            date = tz.localize(diff["timestamp"])
            fe = fg.add_entry()
            fe.author({"name": "sec-certs", "email": "webmaster@seccerts.org"})
            fe.title(
                {
                    "back": "Certificate reappeared",
                    "change": "Certificate changed",
                    "new": "New certificate",
                    "remove": "Certificate removed",
                }[diff["type"]]
            )
            fe.id(entry_url + "/" + str(diff["_id"]))
            fe.content(str(render), type="html")
            fe.published(date)
            fe.updated(date)
            if last_update is None or date > last_update:
                last_update = date

        fg.lastBuildDate(last_update)
        fg.updated(last_update)
        return Response(fg.atom_str(pretty=True), mimetype="application/atom+xml")
    else:
        return abort(404)


@fips.route("/id/<int:cert_id>")
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
        ids = list(mongo.db.fips.find({"web_data.module_name": name}, {"_id": 1}))
    if ids:
        if len(ids) == 1:
            return redirect(url_for("fips.entry", hashid=ids[0]["_id"]))
        else:
            docs = list(map(load, mongo.db.fips.find({"_id": {"$in": list(map(itemgetter("_id"), ids))}})))
            return render_template("fips/entry/disambiguate.html.jinja2", certs=docs, name=name)
    else:
        return abort(404)


@sitemap.register_generator
def sitemap_urls():
    yield "fips.index", {}
    yield "fips.dataset", {}
    yield "fips.network", {}
    yield "fips.analysis", {}
    yield "fips.search", {}
    yield "fips.rand", {}
    yield "fips.mip_index", {}
    yield "fips.iut_index", {}
    for doc in mongo.db.fips.find({}, {"_id": 1}):
        yield "fips.entry", {"hashid": doc["_id"]}
    for doc in mongo.db.fips_mip.find({}, {"_id": 1}):
        yield "fips.mip_snapshot", {"id": doc["_id"]}
    for doc in mongo.db.fips_iut.find({}, {"_id": 1}):
        yield "fips.iut_snapshot", {"id": doc["_id"]}
