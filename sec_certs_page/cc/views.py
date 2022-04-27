"""Common Criteria views."""
import operator
import random
from functools import reduce
from operator import itemgetter
from pathlib import Path

import pymongo
import sentry_sdk
from flask import abort, current_app, redirect, render_template, request, send_file, url_for
from flask_breadcrumbs import register_breadcrumb
from flask_cachecontrol import cache_for
from networkx import node_link_data
from werkzeug.exceptions import BadRequest
from werkzeug.utils import safe_join
from whoosh import highlight
from whoosh.qparser import QueryParser, query

from .. import cache, mongo, sitemap
from ..common.objformats import StorageFormat, load
from ..common.search import index_schema
from ..common.views import (
    Pagination,
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
    cc_sars,
    cc_sfrs,
    cc_status,
    get_cc_analysis,
    get_cc_graphs,
    get_cc_map,
    get_cc_searcher,
)


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


@cc.app_template_global("get_cc_eal")
def get_cc_eal(name):
    """Get the long name for the CC EAL."""
    return cc_eals.get(name, None)


@cc.route("/eals.json")
@cache.cached(60 * 60)
def eals():
    """Endpoint with CC EALs JSON."""
    return send_json_attachment(cc_eals)


@cc.route("/status.json")
@cache.cached(60 * 60)
def statuses():
    """Endpoint with CC status JSON."""
    return send_json_attachment(cc_status)


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
    return render_template("cc/network.html.jinja2")


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

    with sentry_sdk.start_span(op="mongo", description="Find certs."):
        cursor = mongo.db.cc.find(query, projection)
        count = mongo.db.cc.count_documents(query)

    if sort == "match" and q is not None and q != "":
        cursor.sort([("score", {"$meta": "textScore"}), ("name", pymongo.ASCENDING)])
    elif sort == "cert_date":
        cursor.sort([("not_valid_before._value", pymongo.ASCENDING)])
    elif sort == "archive_date":
        cursor.sort([("not_valid_after._value", pymongo.ASCENDING)])
    else:
        cursor.sort([("name", pymongo.ASCENDING)])

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
        total=mongo.db.cc.count_documents({}),
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


@cc.route("/search/")
@register_breadcrumb(cc, ".search", "Search")
def search():
    """Common criteria search."""
    res = process_search(request)
    return render_template(
        "cc/search/index.html.jinja2",
        **res,
        title=f"Common Criteria [{res['q'] if res['q'] else ''}] ({res['page']}) | seccerts.org",
    )


@cc.route("/ftsearch/")
@register_breadcrumb(cc, ".fulltext_search", "Fulltext search")
def fulltext_search():
    categories = cc_categories.copy()
    try:
        page = int(request.args.get("page", 1))
    except ValueError:
        raise BadRequest(description="Invalid page number.")
    q = request.args.get("q", None)
    cat = request.args.get("cat", None)
    q_filter = query.Term("cert_schema", "cc")
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

    status = request.args.get("status", "any")
    if status not in ("any", "active", "archived"):
        raise BadRequest(description="Invalid status.")
    if status != "any":
        q_filter &= query.Term("status", status)

    if q is None:
        return render_template(
            "cc/search/fulltext.html.jinja2",
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
        searcher = get_cc_searcher()
    with sentry_sdk.start_span(op="whoosh.search", description=f"Search {qr}"):
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
    with sentry_sdk.start_span(op="whoosh.highlight", description="Highlight results"):
        for hit in res:
            dgst = hit["dgst"]
            cert = mongo.db.cc.find_one({"_id": dgst})
            entry = {"hit": hit, "cert": cert}
            fpath = entry_file_path(dgst, current_app.config["DATASET_PATH_CC_DIR"], hit["document_type"], "txt")
            try:
                with open(fpath) as f:
                    contents = f.read()
                hlt = hit.highlights("content", text=contents)
                entry["highlights"] = hlt
            except FileNotFoundError:
                pass
            results.append(entry)

    pagination = Pagination(
        page=page,
        per_page=per_page,
        search=True,
        found=count,
        total=mongo.db.cc.count_documents({}),
        css_framework="bootstrap5",
        alignment="center",
    )
    return render_template(
        "cc/search/fulltext.html.jinja2",
        q=q,
        results=results,
        categories=categories,
        status=status,
        pagination=pagination,
        document_type=type,
        runtime=runtime,
    )


@cc.route("/search/pagination/")
def search_pagination():
    """Common criteria search (raw pagination)."""

    def callback(**kwargs):
        return url_for(".search", **kwargs)

    res = process_search(request, callback=callback)
    return render_template("cc/search/pagination.html.jinja2", **res)


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
        with sentry_sdk.start_span(op="mongo", description="Find diffs"):
            diffs = list(mongo.db.cc_diff.find({"dgst": hashid}, sort=[("timestamp", pymongo.ASCENDING)]))
            diff_jsons = list(map(lambda x: StorageFormat(x).to_json_mapping(), diffs))
            diffs = list(map(load, diffs))
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
        return render_template(
            "cc/entry/index.html.jinja2",
            cert=doc,
            hashid=hashid,
            profiles=profiles,
            diffs=diffs,
            diff_jsons=diff_jsons,
            cves=cves,
            cpes=cpes,
            local_files=local_files,
            json=StorageFormat(raw_doc).to_json_mapping(),
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
