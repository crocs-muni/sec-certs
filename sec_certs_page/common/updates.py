import pymongo
from bson import ObjectId
from flask import render_template, request

from .. import mongo


def get_latest_run_id(log_collection: str) -> ObjectId | None:
    run = mongo.db[log_collection].find_one(
        {"ok": True}, sort=[("end_time", pymongo.DESCENDING)], projection={"_id": 1}
    )
    return run["_id"] if run else None


def get_dgsts_by_diff_type(diff_collection: str, run_id: ObjectId, diff_type: str):
    return {d["dgst"] for d in mongo.db[diff_collection].find({"run_id": run_id, "type": diff_type}, {"dgst": 1})}


def get_recent_runs(log_collection: str, limit: int | None = None) -> list[dict]:
    runs = (
        mongo.db[log_collection]
        .find({"ok": True}, projection={"_id": 1, "start_time": 1, "end_time": 1})
        .sort([("end_time", pymongo.DESCENDING)])
    )
    return list(runs.limit(limit) if limit else runs)


def render_updates(search_cls, scheme: str, title: str):
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    page = "results" if is_ajax else "index"
    res = search_cls.process_search(request)
    return render_template(
        f"{scheme}/updates/{page}.html.jinja2",
        **res,
        runs=get_recent_runs(search_cls.log_collection),
        run=mongo.db[search_cls.log_collection].find_one({"_id": res["run_id"]}),
        title=title,
    )
