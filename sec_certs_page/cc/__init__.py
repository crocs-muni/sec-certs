import json
from contextvars import ContextVar
from datetime import date, datetime

import sentry_sdk
from flask import Blueprint, current_app, url_for
from pymongo.errors import OperationFailure

from .. import mongo, whoosh_index
from ..common.objformats import load
from ..common.views import create_graph

cc: Blueprint = Blueprint("cc", __name__, url_prefix="/cc")
cc.cli.short_help = "Common Criteria commands."

cc_mem_graphs: ContextVar = ContextVar("cc_graphs")
cc_mem_analysis: ContextVar = ContextVar("cc_analysis")
cc_mem_map: ContextVar = ContextVar("cc_map")
cc_mem_changes: ContextVar = ContextVar("cc_changes")

with cc.open_resource("sfrs.json") as f:
    cc_sfrs = json.load(f)
with cc.open_resource("sars.json") as f:
    cc_sars = json.load(f)
with cc.open_resource("categories.json") as f:
    cc_categories = json.load(f)
with cc.open_resource("eals.json") as f:
    cc_eals = json.load(f)
with cc.open_resource("status.json") as f:
    cc_status = json.load(f)

cc_searcher: ContextVar = ContextVar("cc_searcher")


def load_cc_data():
    with sentry_sdk.start_span(op="cc.load", description="Load CC data"):
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
                "heuristics.st_references.directly_referencing": 1,
                "heuristics.report_references.directly_referencing": 1,
            },
        )
        cc_references = {}
        for cert in data:
            cert = load(cert)
            hashid = cert["_id"]
            cert_id = cert["heuristics"]["cert_id"]
            refs = []
            if cert["heuristics"]["report_references"]["directly_referencing"]:
                refs.extend(cert["heuristics"]["report_references"]["directly_referencing"])
            if cert["heuristics"]["st_references"]["directly_referencing"]:
                refs.extend(cert["heuristics"]["st_references"]["directly_referencing"])
            if not cert_id:
                continue
            reference = {
                "hashid": hashid,
                "name": cert["name"],
                "refs": refs,
                "href": url_for("cc.entry", hashid=hashid),
                "type": cc_categories[cert["category"]]["id"],
                "status": cert["status"],
            }
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
            cert_month = date.fromisoformat(cert["not_valid_before"]["_value"]).replace(day=1).strftime("%Y-%m-%d")
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
        try:
            while changes is not None and changes.alive and changes.try_next():
                do_update = True
        except OperationFailure:
            changes = mongo.db.cc.watch(batch_size=100, max_await_time_ms=50)
            cc_mem_changes.set(changes)
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


def get_cc_searcher():
    try:
        searcher = cc_searcher.get()
        searcher = searcher.refresh()
    except LookupError:
        searcher = whoosh_index.searcher()
    cc_searcher.set(searcher)
    return searcher


@cc.before_app_first_request
def init_cc():
    load_cc_data()
    get_cc_searcher()


from .commands import *
from .views import *