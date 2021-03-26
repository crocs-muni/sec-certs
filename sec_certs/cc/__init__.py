import json
import gc
from collections import namedtuple
from sys import getsizeof
from datetime import datetime
from hashlib import blake2b

from flask import Blueprint
from pkg_resources import resource_stream
from networkx import info as graph_info

from sec_certs.utils import create_graph

cc = Blueprint("cc", __name__, url_prefix="/cc")

cc_names = []
cc_data = {}
cc_graphs = []
cc_analysis = {}
cc_map = {}
cc_sfrs = {}
cc_sars = {}
cc_categories = {}

CCEntry = namedtuple("CCEntry", ("name", "hashid", "status", "cert_date", "archived_date", "category", "search_name"))


@cc.before_app_first_request
def load_cc_data():
    global cc_names, cc_data, cc_graphs, cc_map, cc_analysis, cc_sfrs, cc_sars, cc_categories
    # Load raw data
    with current_app.open_instance_resource("cc.json") as f:
        data = f.read()
        loaded_cc_data = json.loads(data)
        del data
    print(" * (CC) Loaded certs")
    with resource_stream("sec_certs.cc", "sfrs.json") as f:
        cc_sfrs = json.load(f)
    print(" * (CC) Loaded SFRs")
    with resource_stream("sec_certs.cc", "sars.json") as f:
        cc_sars = json.load(f)
    print(" * (CC) Loaded SARs")
    with resource_stream("sec_certs.cc", "categories.json") as f:
        cc_categories = json.load(f)
    print(" * (CC) Loaded categories")

    # Create ids
    cc_data = {blake2b(key.encode(), digest_size=10).hexdigest(): value for key, value in loaded_cc_data.items()}
    del loaded_cc_data
    cc_names = list(sorted(CCEntry(value["csv_scan"]["cert_item_name"], key, value["csv_scan"]["cert_status"],
                                   datetime.strptime(value["csv_scan"]["cc_certification_date"], "%m/%d/%Y"),
                                   datetime.strptime(value["csv_scan"]["cc_archived_date"], "%m/%d/%Y") if
                                   value["csv_scan"]["cc_archived_date"] else value["csv_scan"]["cc_archived_date"],
                                   value["csv_scan"]["cc_category"], value["csv_scan"]["cert_item_name"].lower())
                           for key, value in cc_data.items()))

    # Extract references
    cc_references = {}
    for hashid, cert in cc_data.items():
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
    print(f" * (CC) Got {len(cc_data)} certificates")
    print(f" * (CC) Got {len(cc_references)} certificates with IDs")
    print(f" * (CC) Got graph:\n{graph_info(cc_graph)}")
    print(" * (CC) Made network")
    del cc_graph

    cc_analysis["categories"] = {}
    for cert in cc_names:
        cc_analysis["categories"].setdefault(cert.category, 0)
        cc_analysis["categories"][cert.category] += 1
    cc_analysis["categories"] = [{"name": key, "value": value} for key, value in cc_analysis["categories"].items()]

    cc_analysis["certified"] = {}
    for cert in cc_names:
        cert_month = cert.cert_date.replace(day=1).strftime("%Y-%m-%d")
        cc_analysis["certified"].setdefault(cert.category, [])
        months = cc_analysis["certified"][cert.category]
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
    print(" * (CC) Performed analysis")

    mem_taken = sum(map(getsizeof, (cc_names, cc_data, cc_graphs, cc_map, cc_sars, cc_sfrs, cc_categories, cc_analysis)))
    print(f" * (CC) Size in memory: {mem_taken}B")
    gc.collect()


from .views import *
