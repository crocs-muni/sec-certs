import json
from sys import getsizeof
import os.path
import random
from hashlib import blake2b

import networkx as nx
from networkx.algorithms.components import weakly_connected_components
from networkx.readwrite.json_graph import node_link_data
from flask import Blueprint, render_template, abort, jsonify, url_for, current_app, request
from pkg_resources import resource_stream

from .utils import Pagination

cc = Blueprint("cc", __name__, url_prefix="/cc")

cc_names = []
cc_data = {}
cc_graphs = []
cc_map = {}
cc_sfrs = {}
cc_sars = {}

cc_categories = {
    'Access Control Devices and Systems': {
        "id": "a",
        "icon": "fa-id-card-alt"
    },
    'Boundary Protection Devices and Systems': {
        "id": "b",
        "icon": "fa-door-closed"
    },
    'Data Protection': {
        "id": "c",
        "icon": "fa-shield-alt"
    },
    'Databases': {
        "id": "d",
        "icon": "fa-database"
    },
    'Detection Devices and Systems': {
        "id": "e",
        "icon": "fa-eye"
    },
    'ICs, Smart Cards and Smart Card-Related Devices and Systems': {
        "id": "f",
        "icon": "fa-credit-card"
    },
    'Key Management Systems': {
        "id": "g",
        "icon": "fa-key"
    },
    'Mobility': {
        "id": "h",
        "icon": "fa-car"
    },
    'Multi-Function Devices': {
        "id": "i",
        "icon": "fa-server"
    },
    'Network and Network-Related Devices and Systems': {
        "id": "j",
        "icon": "fa-network-wired"
    },
    'Operating Systems': {
        "id": "k",
        "icon": "fa-desktop"
    },
    'Other Devices and Systems': {
        "id": "l",
        "icon": "fa-square"
    },
    'Products for Digital Signatures': {
        "id": "m",
        "icon": "fa-signature"
    },
    'Trusted Computing': {
        "id": "o",
        "icon": "fa-microchip"
    },
    'Biometric Systems and Devices': {
        "id": "p",
        "icon": "fa-fingerprint"
    }
}


@cc.before_app_first_request
def load_cc_data():
    global cc_names, cc_data, cc_graphs, cc_map, cc_sfrs, cc_sars
    # Load raw data
    with open(os.path.join(current_app.instance_path, "cc.json")) as f:
        loaded_cc_data = json.load(f)
    print(" * (CC) Loaded certs")

    # Create ids
    cc_data = {blake2b(key.encode(), digest_size=20).hexdigest(): value for key, value in loaded_cc_data.items()}
    cc_names = list(sorted((value["csv_scan"]["cert_item_name"], key, value["csv_scan"]["cert_status"],
                            value["csv_scan"]["cc_certification_date"], value["csv_scan"]["cc_archived_date"],
                            value["csv_scan"]["cc_category"]) for key, value in cc_data.items()))

    # Extract references
    cc_references = {}
    for hashid, cert in cc_data.items():
        if "processed" in cert and "cert_id" in cert["processed"] and cert["processed"]["cert_id"] != "":
            cert_id = cert["processed"]["cert_id"]
        else:
            continue
        reference = {
            "hashid": hashid,
            "name": cert["csv_scan"]["cert_item_name"],
            "refs": []
        }
        if "keywords_scan" in cert and cert["keywords_scan"]["rules_cert_id"]:
            items = sum(map(lambda x: list(x.keys()), cert["keywords_scan"]["rules_cert_id"].values()), [])
            reference["refs"].extend(items)
        if "st_keywords_scan" in cert and cert["st_keywords_scan"]["rules_cert_id"]:
            items = sum(map(lambda x: list(x.keys()), cert["st_keywords_scan"]["rules_cert_id"].values()), [])
            reference["refs"].extend(items)
        cc_references[cert_id] = reference

    # Create graph
    cc_graph = nx.DiGraph()
    for key, value in cc_references.items():
        cc_graph.add_node(value["hashid"], certid=key, name=value["name"],
                          href=url_for("cc.entry", hashid=value["hashid"]))
    for cert_id, reference in cc_references.items():
        for ref_id in set(reference["refs"]):
            if ref_id in cc_references and ref_id != cert_id:
                cc_graph.add_edge(reference["hashid"], cc_references[ref_id]["hashid"])
    cc_graphs = []
    for component in weakly_connected_components(cc_graph):
        subgraph = cc_graph.subgraph(component)
        cc_graphs.append(subgraph)
        for node in subgraph:
            cc_map[str(node)] = subgraph
    print(f" * (CC) Got {len(cc_data)} certificates")
    print(f" * (CC) Got {len(cc_references)} certificates with IDs")
    print(f" * (CC) Got {len(cc_graphs)} graph components")
    print(" * (CC) Made network")

    with resource_stream("sec_certs", "cc_sfrs.json") as f:
        cc_sfrs = json.load(f)
    print(" * (CC) Loaded SFRs")
    with resource_stream("sec_certs", "cc_sars.json") as f:
        cc_sars = json.load(f)
    print(" * (CC) Loaded SARs")
    mem_taken = getsizeof(cc_names) + getsizeof(cc_data) + getsizeof(cc_graphs) + getsizeof(cc_sfrs) + getsizeof(
        cc_sars)
    print(f" * (CC) Size in memory: {mem_taken}B")


@cc.app_template_global("get_cc_sar")
def get_cc_sar(sar):
    return cc_sars.get(sar, None)


@cc.app_template_global("get_cc_sfr")
def ger_cc_sfr(sfr):
    return cc_sfrs.get(sfr, None)


@cc.route("/")
@cc.route("/<int:page>/")
def index(page=1):
    per_page = 40
    pagination = Pagination(page=page, per_page=per_page, total=len(cc_names), href=url_for(".index") + "{0}/",
                            css_framework="bootstrap4", alignment="center")
    return render_template("cc/index.html.jinja2", certs=cc_names[(page - 1) * per_page:page * per_page],
                           pagination=pagination, title=f"Common Criteria ({page}) | seccerts.org")


@cc.route("/network/")
def network():
    nodes = []
    edges = []
    for graph in cc_graphs:
        link_data = node_link_data(graph)
        nodes.extend(link_data["nodes"])
        edges.extend(link_data["links"])
    random.shuffle(nodes)
    network = {
        "nodes": nodes,
        "links": edges
    }
    return render_template("cc/network.html.jinja2", network=network, title="Common Criteria network | seccerts.org")


def process_search(request, callback=None):
    if request.args:
        page = int(request.args.get("page", 1))
        q = request.args.get("q", None)
        cat = request.args.get("cat", None)
    else:
        page = 1
        q = None
        cat = None

    categories = cc_categories.copy()
    names = cc_names

    if cat is not None:
        ids = cat.split(",")
        for category in categories.values():
            if category["id"] in ids:
                category["selected"] = True
            else:
                category["selected"] = False
        names = list(filter(lambda x: categories[x[5]]["selected"], names))
    else:
        for category in categories.values():
            category["selected"] = True

    if q is not None:
        names = list(filter(lambda x: q.lower() in x[0].lower(), names))

    per_page = 40
    pagination = Pagination(page=page, per_page=per_page, search=True, found=len(names), total=len(cc_names),
                            css_framework="bootstrap4", alignment="center",
                            url_callback=callback)
    return {
        "pagination": pagination,
        "certs": names[(page - 1) * per_page:page * per_page],
        "categories": categories,
        "q": q,
        "page": page
    }


@cc.route("/search/")
def search():
    res = process_search(request)
    return render_template("cc/search.html.jinja2", **res, title=f"Common Criteria [{res['q']}] ({res['page']}) | seccerts.org")


@cc.route("/search/pagination")
def search_pagination():
    def callback(**kwargs):
        return url_for(".search", **kwargs)

    res = process_search(request, callback=callback)
    return render_template("cc/search_pagination.html.jinja2", **res)


@cc.route("/<string(length=40):hashid>/")
def entry(hashid):
    if hashid in cc_data.keys():
        cert = cc_data[hashid]
        if hashid in cc_map.keys():
            graph = cc_map[hashid]
            network = node_link_data(graph)
        else:
            network = {}
        return render_template("cc/entry.html.jinja2", cert=cert, network=network, hashid=hashid,
                               title=cert["csv_scan"]["cert_item_name"] + " | seccerts.org")
    else:
        return abort(404)


@cc.route("/<string(length=40):hashid>/graph.json")
def entry_graph_json(hashid):
    if hashid in cc_data.keys():
        if hashid in cc_map.keys():
            graph = cc_map[hashid]
            network = node_link_data(graph)
        else:
            network = {}
        resp = jsonify(network)
        resp.headers['Content-Disposition'] = 'attachment'
        return resp
    else:
        return abort(404)


@cc.route("/<string(length=40):hashid>/cert.json")
def entry_json(hashid):
    if hashid in cc_data.keys():
        resp = jsonify(cc_data[hashid])
        resp.headers['Content-Disposition'] = 'attachment'
        return resp
    else:
        return abort(404)
