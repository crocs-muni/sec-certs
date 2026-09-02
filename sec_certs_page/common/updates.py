import pymongo
from bson import ObjectId

from .. import mongo


def get_latest_run_id(log_collection: str) -> ObjectId | None:
    run = mongo.db[log_collection].find_one(
        {"ok": True}, sort=[("end_time", pymongo.DESCENDING)], projection={"_id": 1}
    )
    return run["_id"] if run else None


def get_dgsts_by_diff_type(diff_collection: str, run_id: ObjectId, diff_type: str):
    return {d["dgst"] for d in mongo.db[diff_collection].find({"run_id": run_id, "type": diff_type}, {"dgst": 1})}
