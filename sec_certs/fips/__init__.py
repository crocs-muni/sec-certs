import atexit
import json
import sentry_sdk
from werkzeug.local import Local
from flask import Blueprint

from .. import mongo
from ..utils import create_graph

fips = Blueprint("fips", __name__, url_prefix="/fips")
fips.cli.short_help = "FIPS 140 commands."

fips_local = Local()
fips_local.graphs = []
fips_local.map = {}
fips_local.changes = None
with fips.open_resource("types.json") as f:
    fips_types = json.load(f)


def load_fips_data():
    global fips_local

    with sentry_sdk.start_span(op="fips.load", description="Load FIPS data"):
        data = mongo.db.fips.find({}, {
            "_id": 1,
            "cert_id": 1,
            "web_scan.module_name": 1,
            "web_scan.module_type": 1,
            "processed.connections": 1
        })
        fips_references = {str(cert["cert_id"]): {
            "hashid": cert["_id"],
            "name": cert["web_scan"]["module_name"],
            "refs": cert["processed"]["connections"],
            "href": url_for("fips.entry", hashid=cert["_id"]),
            "type": fips_types[cert["web_scan"]["module_type"]]["id"] if cert["web_scan"][
                                                                             "module_type"] in fips_types else ""
        } for cert in data}

    with sentry_sdk.start_span(op="fips.load", description="Compute FIPS graph"):
        fips_graph, fips_graphs, fips_map = create_graph(fips_references)
        del fips_graph
    fips_local.graphs = fips_graphs
    fips_local.map = fips_map


@fips.before_app_first_request
def _init_fips_data():
    global fips_local
    fips_local.graphs = []
    fips_local.map = {}
    fips_local.changes = mongo.db.fips.watch()
    load_fips_data()


def _update_fips_data():
    do_update = False
    while fips_local and fips_local.changes.alive and fips_local.changes.try_next():
        do_update = True
    if do_update:
        load_fips_data()


def get_fips_graphs():
    _update_fips_data()
    return fips_local.graphs


def get_fips_map():
    _update_fips_data()
    return fips_local.map


from .commands import *
from .views import *
