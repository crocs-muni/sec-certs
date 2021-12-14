import json
from contextvars import ContextVar
from datetime import datetime
import subprocess

import sentry_sdk
from celery.schedules import crontab
from flask import Blueprint

from .. import mongo, celery, app
from ..utils import create_graph

cc = Blueprint("cc", __name__, url_prefix="/cc")
cc.cli.short_help = "Common Criteria commands."

cc_mem_graphs = ContextVar("cc_graphs")
cc_mem_analysis = ContextVar("cc_analysis")
cc_mem_map = ContextVar("cc_map")
cc_mem_changes = ContextVar("cc_changes")

with cc.open_resource("sfrs.json") as f:
    cc_sfrs = json.load(f)
with cc.open_resource("sars.json") as f:
    cc_sars = json.load(f)
with cc.open_resource("categories.json") as f:
    cc_categories = json.load(f)


def load_cc_data():
    with sentry_sdk.start_span(op="cc.load", description="Load CC data"):
        # Extract references
        data = mongo.db.cc.find({}, {
            "_id": 1,
            "name": 1,
            "category": 1,
            "not_valid_before": 1,
            "heuristics.cert_id": 1,
            "pdf_data.st_keywords.rules_cert_id": 1,
            "pdf_data.report_keywords.rules_cert_id": 1
        })
        cc_references = {}
        for cert in data:
            hashid = cert["_id"]
            cert_id = cert["heuristics"]["cert_id"]
            if not cert_id:
                continue
            reference = {
                "hashid": hashid,
                "name": cert["name"],
                "refs": [],
                "href": url_for("cc.entry", hashid=hashid),
                "type": cc_categories[cert["category"]]["id"]
            }
            # Process references
            if current_app.config["CC_GRAPH"] in ("BOTH", "CERT_ONLY") and \
                    cert["pdf_data"]["report_keywords"]["rules_cert_id"]:
                # Add references from cert
                reference["refs"].extend(cert["pdf_data"]["report_keywords"]["rules_cert_id"].keys())
            if current_app.config["CC_GRAPH"] in ("BOTH", "ST_ONLY") and \
                    cert["pdf_data"]["st_keywords"]["rules_cert_id"]:
                # Add references from security target
                reference["refs"].extend(cert["pdf_data"]["st_keywords"]["rules_cert_id"].keys())
            cc_references[cert_id] = reference

    with sentry_sdk.start_span(op="cc.load", description="Compute CC graph"):
        cc_graph, cc_graphs, cc_map = create_graph(cc_references)
        del cc_graph
        cc_mem_graphs.set(cc_graphs)
        cc_mem_map.set(cc_map)

    with sentry_sdk.start_span(op="cc.load", description="Compute CC analysis"):
        cc_analysis = {}
        cc_analysis["categories"] = {}
        for cert in data.clone():
            cc_analysis["categories"].setdefault(cert["category"], 0)
            cc_analysis["categories"][cert["category"]] += 1
        cc_analysis["categories"] = [{"name": key, "value": value} for key, value in cc_analysis["categories"].items()]

        cc_analysis["certified"] = {}
        for cert in data.clone():
            cert_month = datetime.strptime(cert["not_valid_before"], "%Y-%m-%d").replace(day=1).strftime("%Y-%m-%d")
            cc_analysis["certified"].setdefault(cert["category"], [])
            months = cc_analysis["certified"][cert["category"]]
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
        cc_mem_analysis.set(cc_analysis)


def _update_cc_data():
    with sentry_sdk.start_span(op="cc.check", description="Check CC staleness"):
        do_update = False
        changes = cc_mem_changes.get(None)
        if changes is None:
            changes = mongo.db.cc.watch(batch_size=100, max_await_time_ms=50)
            cc_mem_changes.set(changes)
            do_update = True
        while changes is not None and changes.alive and changes.try_next():
            do_update = True
    if do_update:
        load_cc_data()


def get_cc_graphs():
    """Get Common Criteria graphs."""
    _update_cc_data()
    return cc_mem_graphs.get()


def get_cc_map():
    """Get Common Criteria mapping of certs to graphs."""
    _update_cc_data()
    return cc_mem_map.get()


def get_cc_analysis():
    """Get Common Criteria analysis results."""
    _update_cc_data()
    return cc_mem_analysis.get()


from .commands import *
from .views import *
from .tasks import update_data


@celery.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    if app.config["UPDATE_TASK_SCHEDULE"]["cc"]:
        sender.add_periodic_task(crontab(*app.config["UPDATE_TASK_SCHEDULE"]["cc"]),
                                 update_data.s(), name="Update CC data.")
