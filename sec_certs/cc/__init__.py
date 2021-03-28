import atexit
import json
from datetime import datetime

from flask import Blueprint

from .. import mongo
from ..utils import create_graph

cc = Blueprint("cc", __name__, url_prefix="/cc")
cc.cli.short_help = "Common Criteria commands."

cc_graphs = []
cc_analysis = {}
cc_map = {}
with cc.open_resource("sfrs.json") as f:
    cc_sfrs = json.load(f)
with cc.open_resource("sars.json") as f:
    cc_sars = json.load(f)
with cc.open_resource("categories.json") as f:
    cc_categories = json.load(f)


@cc.before_app_first_request
def load_cc_data():
    global cc_graphs, cc_analysis, cc_map
    # Extract references
    data = mongo.db.cc.find({}, {
        "_id": 1,
        "csv_scan.cert_item_name": 1,
        "csv_scan.cc_category": 1,
        "csv_scan.cc_certification_date": 1,
        "processed.cert_id": 1,
        "keywords_scan.rules_cert_id": 1,
        "st_keywords_scan.rules_cert_id": 1
    })
    cc_references = {}
    for cert in data:
        hashid = cert["_id"]
        if "processed" in cert and "cert_id" in cert["processed"] and cert["processed"]["cert_id"] != "":
            cert_id = cert["processed"]["cert_id"]
        else:
            continue
        reference = {
            "hashid": hashid,
            "name": cert["csv_scan"]["cert_item_name"],
            "refs": [],
            "href": url_for("cc.entry", hashid=hashid),
            "type": cc_categories[cert["csv_scan"]["cc_category"]]["id"]
        }

        if current_app.config["CC_GRAPH"] in ("BOTH", "CERT_ONLY") and "keywords_scan" in cert and \
                cert["keywords_scan"]["rules_cert_id"]:
            items = sum(map(lambda x: list(x.keys()), cert["keywords_scan"]["rules_cert_id"].values()), [])
            reference["refs"].extend(items)
        if current_app.config["CC_GRAPH"] in ("BOTH", "ST_ONLY") and "st_keywords_scan" in cert and \
                cert["st_keywords_scan"]["rules_cert_id"]:
            items = sum(map(lambda x: list(x.keys()), cert["st_keywords_scan"]["rules_cert_id"].values()), [])
            reference["refs"].extend(items)
        cc_references[cert_id] = reference

    cc_graph, cc_graphs, cc_map = create_graph(cc_references)
    del cc_graph

    cc_analysis["categories"] = {}
    for cert in data.clone():
        cc_analysis["categories"].setdefault(cert["csv_scan"]["cc_category"], 0)
        cc_analysis["categories"][cert["csv_scan"]["cc_category"]] += 1
    cc_analysis["categories"] = [{"name": key, "value": value} for key, value in cc_analysis["categories"].items()]

    cc_analysis["certified"] = {}
    for cert in data.clone():
        cert_month = datetime.strptime(cert["csv_scan"]["cc_certification_date"], "%m/%d/%Y").replace(day=1).strftime("%Y-%m-%d")
        cc_analysis["certified"].setdefault(cert["csv_scan"]["cc_category"], [])
        months = cc_analysis["certified"][cert["csv_scan"]["cc_category"]]
        for month in months:
            if month["date"] == cert_month:
                month["value"] += 1
                break
        else:
            months.append({"date": cert_month, "value": 1})
    certified = {}
    for category, months in cc_analysis["certified"].items():
        for month in months:
            if month["date"] in certified:
                certified[month["date"]][category] = month["value"]
            else:
                certified[month["date"]] = {category: month["value"]}
    certified = [{"date": key, **value} for key, value in certified.items()]
    for category in cc_analysis["certified"].keys():
        for month in certified:
            if category not in month.keys():
                month[category] = 0
    cc_analysis["certified"] = list(sorted(certified, key=lambda x: x["date"]))


cc_changes = mongo.db.cc.watch()


def _update_cc_data():
    do_update = False
    while cc_changes.alive and cc_changes.try_next():
        do_update = True
    if do_update:
        load_cc_data()


def get_cc_graphs():
    _update_cc_data()
    return cc_graphs


def get_cc_map():
    _update_cc_data()
    return cc_map


def get_cc_analysis():
    _update_cc_data()
    return cc_analysis


def _close_changes_watch():
    cc_changes.close()


atexit.register(_close_changes_watch)


from .commands import *
from .views import *
