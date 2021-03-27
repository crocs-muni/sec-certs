from datetime import datetime
import json
import gc
from collections import namedtuple
from sys import getsizeof
from hashlib import blake2b

from flask import Blueprint

from networkx import info as graph_info

from sec_certs.utils import create_graph

fips = Blueprint("fips", __name__, url_prefix="/fips")

fips_data = {}
fips_names = []
fips_graphs = []
fips_map = {}
fips_types = {}

FIPSEntry = namedtuple("FIPSEntry", ("id", "name", "hashid", "status", "level", "vendor", "type", "cert_dates", "sunset_date", "search_name"))


@fips.before_app_first_request
def load_fips_data():
    global fips_names, fips_data, fips_graphs, fips_map, fips_types
    with current_app.open_instance_resource("fips.json") as f:
        data = f.read()
        loaded_fips_data = json.loads(data)
        del data
    with fips.open_resource("types.json") as f:
        fips_types = json.load(f)
    print(" * (FIPS) Loaded types")
    fips_data = {blake2b(key.encode(), digest_size=10).hexdigest(): value for key, value in
                 loaded_fips_data["certs"].items()}
    del loaded_fips_data

    def _parse_date(cert, date):
        return datetime.strptime(date, "%Y-%m-%d 00:00:00")
    fips_names = list(sorted(FIPSEntry(int(value["cert_id"]), value["web_scan"]["module_name"], key, value["web_scan"]["status"],
                                       value["web_scan"]["level"], value["web_scan"]["vendor"], value["web_scan"]["module_type"],
                                       [_parse_date(value, date) for date in value["web_scan"]["date_validation"]],
                                       _parse_date(value, value["web_scan"]["date_sunset"]) if value["web_scan"]["date_sunset"] else None,
                                       value["web_scan"]["module_name"].lower() if value["web_scan"]["module_name"] else "") for key, value in
                             fips_data.items()))
    print(" * (FIPS) Loaded certs")

    fips_references = {cert["cert_id"]: {
        "hashid": hashid,
        "name": cert["web_scan"]["module_name"],
        "refs": cert["processed"]["connections"],
        "href": url_for("fips.entry", hashid=hashid),
        "type": fips_types[cert["web_scan"]["module_type"]]["id"] if cert["web_scan"]["module_type"] in fips_types else ""
    } for hashid, cert in fips_data.items()}

    fips_graph, fips_graphs, fips_map = create_graph(fips_references)
    print(f" * (FIPS) Got {len(fips_data)} certificates")
    print(f" * (FIPS) Got {len(fips_references)} certificates with IDs")
    print(f" * (FIPS) Got graph:\n{graph_info(fips_graph)}")
    print(" * (FIPS) Made network")
    del fips_graph

    mem_taken = sum(map(getsizeof, (fips_names, fips_data, fips_graphs, fips_map, fips_types)))
    print(f" * (FIPS) Size in memory: {mem_taken}B")
    gc.collect()


from .views import *
