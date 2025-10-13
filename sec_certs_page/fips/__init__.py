import json

import bson
import pymongo
from flask import Blueprint

from .. import cache, mongo, redis
from ..common.views import create_graph

fips: Blueprint = Blueprint("fips", __name__, url_prefix="/fips")
fips.cli.short_help = "FIPS 140 commands."

with fips.open_resource("resources/types.json") as f:
    fips_types = json.load(f)
with fips.open_resource("resources/status.json") as f:
    fips_status = json.load(f)
with fips.open_resource("resources/reference_types.json") as f:
    fips_reference_types = json.load(f)


def latest_run() -> bson.ObjectId:
    """Get the latest FIPS processing run ID."""
    result = mongo.db.fips_log.find_one({"ok": True}, sort=[("end_time", pymongo.DESCENDING)], projection={"_id": 1})
    if result is not None:
        return result["_id"]
    return None


@cache.cached(timeout=3600, make_cache_key=lambda: "fips_references/" + str(latest_run()))
def get_fips_references():
    data = mongo.db.fips.find(
        {},
        {
            "_id": 1,
            "cert_id": 1,
            "web_data.module_name": 1,
            "web_data.module_type": 1,
            "web_data.status": 1,
            "heuristics.related_cves": 1,
            "heuristics.policy_processed_references.directly_referencing": 1,
            "heuristics.module_processed_references.directly_referencing": 1,
        },
    )
    fips_references = {}
    for cert in data:
        cert = load(cert)
        refs = {}
        if cert["heuristics"]["policy_processed_references"]["directly_referencing"]:
            refs["st"] = cert["heuristics"]["policy_processed_references"]["directly_referencing"]
        if cert["heuristics"]["module_processed_references"]["directly_referencing"]:
            refs["web"] = cert["heuristics"]["module_processed_references"]["directly_referencing"]
        reference = {
            "hashid": cert["_id"],
            "name": cert["web_data"]["module_name"],
            "refs": refs,
            "vuln": cert["heuristics"]["related_cves"] is not None,
            "href": url_for("fips.entry", hashid=cert["_id"]),
            "type": (
                fips_types[cert["web_data"]["module_type"]]["id"]
                if cert["web_data"]["module_type"] in fips_types
                else ""
            ),
            "status": cert["web_data"]["status"],
        }
        fips_references[str(cert["cert_id"])] = reference

    _, _, fips_map = create_graph(fips_references)
    return fips_map


@cache.cached(timeout=3600, make_cache_key=lambda: "fips_standards/" + str(latest_run()))
def get_fips_standards():
    """Get FIPS standards."""
    res = mongo.db.fips.aggregate(
        [
            {
                "$project": {
                    "standard": "$web_data.standard",
                    "validation_entry": {"$arrayElemAt": ["$web_data.validation_history", 0]},
                }
            },
            {"$project": {"standard": 1, "date": {"$dateFromString": {"dateString": "$validation_entry.date._value"}}}},
            {
                "$project": {
                    "standard": 1,
                    "year": {"$year": "$date"},
                    "month": {"$month": "$date"},
                }
            },
            {"$group": {"_id": {"standard": "$standard", "year": "$year", "month": "$month"}, "count": {"$sum": 1}}},
            {"$sort": {"_id.year": 1, "_id.month": 1, "count": -1}},
        ]
    )
    return list(res)


from .commands import *
from .dash import *
from .views import *  # noqa
