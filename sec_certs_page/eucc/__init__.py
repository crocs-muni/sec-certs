import json

import bson
from flask import Blueprint

eucc: Blueprint = Blueprint("eucc", __name__, url_prefix="/eucc")
eucc.cli.short_help = "EUCC commands."

with eucc.open_resource("../common/resources/schemes.json") as f:
    eucc_schemes = json.load(f)
with eucc.open_resource("../common/resources/sfrs.json") as f:
    eucc_sfrs = json.load(f)
with eucc.open_resource("../common/resources/sars.json") as f:
    eucc_sars = json.load(f)
with eucc.open_resource("../common/resources/eals.json") as f:
    eucc_eals = json.load(f)
with eucc.open_resource("../common/resources/status.json") as f:
    eucc_status = json.load(f)
with eucc.open_resource("../common/resources/reference_types.json") as f:
    eucc_reference_types = json.load(f)

def latest_run() -> bson.ObjectId:
    """Get the latest CC processing run ID."""
    result = mongo.db.eucc_log.find_one({"ok": True}, sort=[("end_time", pymongo.DESCENDING)], projection={"_id": 1})
    if result is None:
        raise RuntimeError("No successful EUCC processing run found in eucc_log.")
    return result["_id"]

from .commands import *
from .views import *