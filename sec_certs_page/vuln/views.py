from pathlib import Path

import sentry_sdk
from flask import abort, current_app, render_template, request, send_file
from flask_breadcrumbs import register_breadcrumb

from .. import mongo, sitemap
from ..common.objformats import load
from . import vuln


@vuln.route("/")
@register_breadcrumb(vuln, ".", "Vulnerability information")
def index():
    return render_template("vuln/index.html.jinja2")


@vuln.route("/cve/cve.json")
def cve_dset():
    dset_path = Path(current_app.instance_path) / current_app.config["DATASET_PATH_CVE"]
    if not dset_path.is_file():
        return abort(404)
    return send_file(
        dset_path,
        as_attachment=True,
        mimetype="application/json",
        download_name="cve.json",
    )


@vuln.route("/cve/cve.json.gz")
def cve_dset_gz():
    dset_path = Path(current_app.instance_path) / current_app.config["DATASET_PATH_CVE_COMPRESSED"]
    if not dset_path.is_file():
        return abort(404)
    return send_file(
        dset_path,
        as_attachment=True,
        mimetype="application/json",
        download_name="cve.json.gz",
    )


@vuln.route("/cve/<string:cve_id>")
@register_breadcrumb(
    vuln,
    ".cve",
    "",
    dynamic_list_constructor=lambda *args, **kwargs: [{"text": request.view_args["cve_id"]}],  # type: ignore
)
def cve(cve_id):
    with sentry_sdk.start_span(op="mongo", description="Find CVE"):
        cve_doc = mongo.db.cve.find_one({"_id": cve_id})
    if not cve_doc:
        return abort(404)

    with sentry_sdk.start_span(op="mongo", description="Find CC certs"):
        cc_certs = list(map(load, mongo.db.cc.find({"heuristics.related_cves._value": cve_id})))
    with sentry_sdk.start_span(op="mongo", description="Find FIPS certs"):
        fips_certs = list(map(load, mongo.db.fips.find({"heuristics.related_cves._value": cve_id})))
    return render_template("vuln/cve.html.jinja2", cve=load(cve_doc), cc_certs=cc_certs, fips_certs=fips_certs)


@vuln.route("/cpe/cpe_match.json")
def cpe_match_dset():
    dset_path = Path(current_app.instance_path) / current_app.config["DATASET_PATH_CPE_MATCH"]
    if not dset_path.is_file():
        return abort(404)
    return send_file(
        dset_path,
        as_attachment=True,
        mimetype="application/json",
        download_name="cpe_match.json",
    )


@vuln.route("/cpe/cpe_match.json.gz")
def cpe_match_dset_gz():
    dset_path = Path(current_app.instance_path) / current_app.config["DATASET_PATH_CPE_MATCH_COMPRESSED"]
    if not dset_path.is_file():
        return abort(404)
    return send_file(
        dset_path,
        as_attachment=True,
        mimetype="application/json",
        download_name="cpe_match.json.gz",
    )


@vuln.route("/cpe/<path:cpe_id>")
@register_breadcrumb(
    vuln,
    ".cpe",
    "",
    dynamic_list_constructor=lambda *args, **kwargs: [{"text": request.view_args["cpe_id"]}],  # type: ignore
)
def cpe(cpe_id):
    with sentry_sdk.start_span(op="mongo", description="Find CPE"):
        cpe_doc = mongo.db.cpe.find_one({"_id": cpe_id})
    if not cpe_doc:
        return abort(404)

    with sentry_sdk.start_span(op="mongo", description="Find CC certs"):
        cc_certs = list(map(load, mongo.db.cc.find({"heuristics.cpe_matches._value": cpe_id})))
    with sentry_sdk.start_span(op="mongo", description="Find FIPS certs"):
        fips_certs = list(map(load, mongo.db.fips.find({"heuristics.cpe_matches._value": cpe_id})))
    with sentry_sdk.start_span(op="mongo", description="Find CVEs"):
        cves = list(map(load, mongo.db.cve.find({"vulnerable_cpes.uri": cpe_id})))
    return render_template(
        "vuln/cpe.html.jinja2", cpe=load(cpe_doc), cc_certs=cc_certs, fips_certs=fips_certs, cves=cves
    )


@vuln.route("/cpe/cpe.json")
def cpe_dset():
    dset_path = Path(current_app.instance_path) / current_app.config["DATASET_PATH_CPE"]
    if not dset_path.is_file():
        return abort(404)
    return send_file(
        dset_path,
        as_attachment=True,
        mimetype="application/json",
        download_name="cpe.json",
    )


@vuln.route("/cpe/cpe.json.gz")
def cpe_dset_gz():
    dset_path = Path(current_app.instance_path) / current_app.config["DATASET_PATH_CPE_COMPRESSED"]
    if not dset_path.is_file():
        return abort(404)
    return send_file(
        dset_path,
        as_attachment=True,
        mimetype="application/json",
        download_name="cpe.json.gz",
    )


@sitemap.register_generator
def sitemap_urls():
    yield "vuln.index", {}
    yield "vuln.cve_dset", {}
    yield "vuln.cve_dset_gz", {}
    yield "vuln.cpe_dset", {}
    yield "vuln.cpe_dset_gz", {}
    yield "vuln.cpe_match_dset", {}
    yield "vuln.cpe_match_dset_gz", {}
    for doc in mongo.db.cve.find({}, {"_id": 1}):
        yield "vuln.cve", {"cve_id": doc["_id"]}
    for doc in mongo.db.cpe.find({}, {"_id": 1}):
        yield "vuln.cpe", {"cpe_id": doc["_id"]}
