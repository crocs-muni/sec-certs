from operator import itemgetter

import sentry_sdk
from flask import abort, current_app, render_template, request

from .. import mongo, sitemap
from ..common.objformats import load
from ..common.views import register_breadcrumb, send_cacheable_instance_file
from . import vuln


@vuln.route("/")
@register_breadcrumb(vuln, ".", "Vulnerability information")
def index():
    return render_template("vuln/index.html.jinja2", title="Vulnerability information | sec-certs.org")


@vuln.route("/search/")
def search():
    return render_template("vuln/search.html.jinja2")


@vuln.route("/data/")
def data():
    return render_template("vuln/data.html.jinja2")


@vuln.route("/cve/cve.json")
def cve_dset():
    return send_cacheable_instance_file(current_app.config["DATASET_PATH_CVE"], "application/json", "cve.json")


@vuln.route("/cve/cve.json.gz")
def cve_dset_gz():
    return send_cacheable_instance_file(
        current_app.config["DATASET_PATH_CVE_COMPRESSED"], "application/gzip", "cve.json.gz"
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
    criteria = set()
    criteria |= set(vuln_cpe["criteria_id"] for vuln_cpe in cve_doc["vulnerable_cpes"])
    for vuln_cfg in cve_doc["vulnerable_criteria_configurations"]:
        for vuln_component in vuln_cfg["components"]:
            criteria |= set(vuln_match["criteria_id"] for vuln_match in vuln_component)

    with sentry_sdk.start_span(op="mongo", description="Find CPE matches"):
        matches = {match["_id"]: match for match in mongo.db.cpe_match.find({"_id": {"$in": list(criteria)}})}

    vuln_configs = []
    for vuln_cpe in cve_doc["vulnerable_cpes"]:
        match = matches.get(vuln_cpe["criteria_id"])
        if match:
            vuln_configs.append((True, list(map(itemgetter("cpeName"), match["matches"])), []))
        # TODO: Maybe include it as well?
    for vuln_cfg in cve_doc["vulnerable_criteria_configurations"]:
        matches_first = []
        for crit in vuln_cfg["components"][0]:
            match = matches.get(crit["criteria_id"])
            if match:
                matches_first.extend(list(map(itemgetter("cpeName"), match["matches"])))
        matches_second = []
        if len(vuln_cfg["components"]) > 1:
            for crit in vuln_cfg["components"][1]:
                match = matches.get(crit["criteria_id"])
                if match:
                    matches_second.extend(list(map(itemgetter("cpeName"), match["matches"])))
        if matches_first and matches_second:
            vuln_configs.append((True, matches_first, matches_second))
        else:
            matches_first = list(map(itemgetter("criteria"), vuln_cfg["components"][0]))
            matches_second = (
                list(map(itemgetter("criteria"), vuln_cfg["components"][1])) if len(vuln_cfg["components"]) > 1 else []
            )
            vuln_configs.append((False, matches_first, matches_second))

    vuln_configs.sort(key=lambda tup: (not tup[0], tup[1], tup[2]))
    with sentry_sdk.start_span(op="mongo", description="Find CC certs"):
        cc_certs = list(map(load, mongo.db.cc.find({"heuristics.related_cves._value": cve_id})))
    with sentry_sdk.start_span(op="mongo", description="Find FIPS certs"):
        fips_certs = list(map(load, mongo.db.fips.find({"heuristics.related_cves._value": cve_id})))
    return render_template(
        "vuln/cve.html.jinja2", cve=load(cve_doc), cc_certs=cc_certs, fips_certs=fips_certs, vuln_configs=vuln_configs
    )


@vuln.route("/cpe/cpe_match.json")
def cpe_match_dset():
    return send_cacheable_instance_file(
        current_app.config["DATASET_PATH_CPE_MATCH"], "application/json", "cpe_match.json"
    )


@vuln.route("/cpe/cpe_match.json.gz")
def cpe_match_dset_gz():
    return send_cacheable_instance_file(
        current_app.config["DATASET_PATH_CPE_MATCH_COMPRESSED"], "application/gzip", "cpe_match.json.gz"
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
        match_ids = list(map(itemgetter("_id"), mongo.db.cpe_match.find({"matches.cpeName": cpe_id}, ["_id"])))
        # XXX: If we want to include the "running on/with" part of the matching then we need one more or
        #      in this statement (for components.1).
        cves = sorted(
            map(
                load,
                mongo.db.cve.find(
                    {
                        "$or": [
                            {"vulnerable_cpes.criteria_id": {"$in": match_ids}},
                            {"vulnerable_criteria_configurations.components.0.criteria_id": {"$in": match_ids}},
                        ]
                    }
                ),
            ),
            key=itemgetter("_id"),
        )
    return render_template(
        "vuln/cpe.html.jinja2", cpe=load(cpe_doc), cc_certs=cc_certs, fips_certs=fips_certs, cves=cves
    )


@vuln.route("/cpe/cpe.json")
def cpe_dset():
    return send_cacheable_instance_file(current_app.config["DATASET_PATH_CPE"], "application/json", "cpe.json")


@vuln.route("/cpe/cpe.json.gz")
def cpe_dset_gz():
    return send_cacheable_instance_file(
        current_app.config["DATASET_PATH_CPE_COMPRESSED"], "application/gzip", "cpe.json.gz"
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
        yield "vuln.cve", {"cve_id": doc["_id"]}, None, None, 0.3
    for doc in mongo.db.cpe.find({}, {"_id": 1}):
        yield "vuln.cpe", {"cpe_id": doc["_id"]}, None, None, 0.1
