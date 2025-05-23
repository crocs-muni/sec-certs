import json
from contextvars import ContextVar

import sentry_sdk
from flask import Blueprint, url_for
from pymongo.errors import OperationFailure

from .. import mongo, redis
from ..common.objformats import load
from ..common.views import create_graph

fips: Blueprint = Blueprint("fips", __name__, url_prefix="/fips")
fips.cli.short_help = "FIPS 140 commands."

fips_mem_init: ContextVar = ContextVar("fips_init")
fips_mem_graphs: ContextVar = ContextVar("fips_graphs")
fips_mem_map: ContextVar = ContextVar("fips_map")
fips_mem_changes: ContextVar = ContextVar("fips_changes")

with fips.open_resource("resources/types.json") as f:
    fips_types = json.load(f)
with fips.open_resource("resources/status.json") as f:
    fips_status = json.load(f)
with fips.open_resource("resources/reference_types.json") as f:
    fips_reference_types = json.load(f)


def load_fips_data():
    with sentry_sdk.start_span(op="fips.load", description="Load FIPS data"):
        fips_mem_init.set(True)

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

    with sentry_sdk.start_span(op="fips.load", description="Compute FIPS graph"):
        fips_graph, fips_graphs, fips_map = create_graph(fips_references)
        del fips_graph
        fips_mem_graphs.set(fips_graphs)
        fips_mem_map.set(fips_map)


def _update_fips_data():
    if not fips_mem_init.get(False):
        load_fips_data()
        return

    with sentry_sdk.start_span(op="fips.check", description="Check FIPS staleness"):
        do_update = False
        lock = redis.lock("fips_update", blocking=False)
        if not lock.locked():
            changes = fips_mem_changes.get(None)
            if changes is None:
                changes = mongo.db.fips.watch(batch_size=100, max_await_time_ms=50)
                fips_mem_changes.set(changes)
                do_update = True
            try:
                while changes and changes.alive and changes.try_next():
                    do_update = True
            except OperationFailure:
                changes = mongo.db.fips.watch(batch_size=100, max_await_time_ms=50)
                fips_mem_changes.set(changes)
                do_update = True
        else:
            # Keep the stale FIPS data if we can't get the lock.
            pass
    if do_update:
        load_fips_data()


def get_fips_graphs():
    _update_fips_data()
    return fips_mem_graphs.get()


def get_fips_map():
    _update_fips_data()
    return fips_mem_map.get()


from .commands import *
from .views import *  # noqa
