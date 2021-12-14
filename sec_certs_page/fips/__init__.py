import json
from contextvars import ContextVar
import sentry_sdk
from flask import Blueprint, current_app
from celery.schedules import crontab

from .. import mongo, celery
from ..utils import create_graph

fips = Blueprint("fips", __name__, url_prefix="/fips")
fips.cli.short_help = "FIPS 140 commands."

fips_mem_graphs = ContextVar("fips_graphs")
fips_mem_map = ContextVar("fips_map")
fips_mem_changes = ContextVar("fips_changes")

with fips.open_resource("types.json") as f:
    fips_types = json.load(f)


def load_fips_data():
    with sentry_sdk.start_span(op="fips.load", description="Load FIPS data"):
        data = mongo.db.fips.find({}, {
            "_id": 1,
            "cert_id": 1,
            "web_scan.module_name": 1,
            "web_scan.module_type": 1,
            "heuristics.connections": 1
        })
        fips_references = {str(cert["cert_id"]): {
            "hashid": cert["_id"],
            "name": cert["web_scan"]["module_name"],
            "refs": cert["heuristics"]["connections"],
            "href": url_for("fips.entry", hashid=cert["_id"]),
            "type": fips_types[cert["web_scan"]["module_type"]]["id"] if cert["web_scan"][
                                                                             "module_type"] in fips_types else ""
        } for cert in data}

    with sentry_sdk.start_span(op="fips.load", description="Compute FIPS graph"):
        fips_graph, fips_graphs, fips_map = create_graph(fips_references)
        del fips_graph
        fips_mem_graphs.set(fips_graphs)
        fips_mem_map.set(fips_map)


def _update_fips_data():
    with sentry_sdk.start_span(op="fips.check", description="Check FIPS staleness"):
        do_update = False
        changes = fips_mem_changes.get(None)
        if changes is None:
            changes = mongo.db.fips.watch(batch_size=100, max_await_time_ms=50)
            fips_mem_changes.set(changes)
            do_update = True
        while changes and changes.alive and changes.try_next():
            do_update = True
    if do_update:
        load_fips_data()


def get_fips_graphs():
    _update_fips_data()
    return fips_mem_graphs.get()


def get_fips_map():
    _update_fips_data()
    return fips_mem_map.get()


from .commands import *
from .views import *
from .tasks import update_data


@celery.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    if current_app.config["UPDATE_TASK_SCHEDULE"]["fips"]:
        sender.add_periodic_task(crontab(*current_app.config["UPDATE_TASK_SCHEDULE"]["fips"]),
                                 update_data.s(), name="Update FIPS data.")