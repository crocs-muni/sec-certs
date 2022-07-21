import sentry_sdk
from flask import abort, render_template, request
from flask_breadcrumbs import register_breadcrumb

from .. import mongo, sitemap
from ..common.objformats import load
from . import vuln


@vuln.route("/")
@register_breadcrumb(vuln, ".", "Vulnerability information")
def index():
    return render_template("vuln/index.html.jinja2")


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


@sitemap.register_generator
def sitemap_urls():
    yield "vuln.index", {}
    for doc in mongo.db.cve.find({}, {"_id": 1}):
        yield "vuln.cve", {"cve_id": doc["_id"]}
    for doc in mongo.db.cpe.find({}, {"_id": 1}):
        yield "vuln.cpe", {"cpe_id": doc["_id"]}
