import json

import bson
import pymongo
from flask import Blueprint

from .. import cache, mongo, redis
from ..common.views import create_graph

cc: Blueprint = Blueprint("cc", __name__, url_prefix="/cc")
cc.cli.short_help = "Common Criteria commands."

with cc.open_resource("resources/sfrs.json") as f:
    cc_sfrs = json.load(f)
with cc.open_resource("resources/sars.json") as f:
    cc_sars = json.load(f)
with cc.open_resource("resources/categories.json") as f:
    cc_categories = json.load(f)
with cc.open_resource("resources/eals.json") as f:
    cc_eals = json.load(f)
with cc.open_resource("resources/status.json") as f:
    cc_status = json.load(f)
with cc.open_resource("resources/reference_types.json") as f:
    cc_reference_types = json.load(f)
with cc.open_resource("resources/schemes.json") as f:
    cc_schemes = json.load(f)


def latest_run() -> bson.ObjectId:
    """Get the latest CC processing run ID."""
    result = mongo.db.cc_log.find_one({"ok": True}, sort=[("end_time", pymongo.DESCENDING)], projection={"_id": 1})
    if result is None:
        raise RuntimeError("No successful CC processing run found in cc_log.")
    return result["_id"]


@cache.cached(timeout=3600, make_cache_key=lambda: "cc_references/" + str(latest_run()))
def get_cc_references():
    # Extract references
    data = mongo.db.cc.find(
        {},
        {
            "_id": 1,
            "name": 1,
            "category": 1,
            "status": 1,
            "not_valid_before": 1,
            "heuristics.cert_id": 1,
            "heuristics.related_cves": 1,
            "heuristics.st_references.directly_referencing": 1,
            "heuristics.report_references.directly_referencing": 1,
        },
    )
    cc_references = {}
    for cert in data:
        cert = load(cert)
        hashid = cert["_id"]
        cert_id = cert["heuristics"]["cert_id"]
        refs = {}
        if cert["heuristics"]["report_references"]["directly_referencing"]:
            refs["report"] = cert["heuristics"]["report_references"]["directly_referencing"]
        if cert["heuristics"]["st_references"]["directly_referencing"]:
            refs["st"] = cert["heuristics"]["st_references"]["directly_referencing"]
        if not cert_id:
            continue
        reference = {
            "hashid": hashid,
            "name": cert["name"],
            "refs": refs,
            "vuln": cert["heuristics"]["related_cves"] is not None,
            "href": url_for("cc.entry", hashid=hashid),
            "type": cc_categories[cert["category"]]["id"],
            "status": cert["status"],
        }
        cc_references[cert_id] = reference

    _, _, cc_map = create_graph(cc_references)
    return cc_map


@cache.cached(timeout=3600, make_cache_key=lambda: "cc_categories/" + str(latest_run()))
def get_cc_categories():
    """Get Common Criteria categories."""
    res = mongo.db.cc.aggregate(
        [
            {"$group": {"_id": "$category", "count": {"$sum": 1}}},
            {"$project": {"_id": 0, "name": "$_id", "value": "$count"}},
        ]
    )
    return list(res)


from .commands import *
from .views import *
