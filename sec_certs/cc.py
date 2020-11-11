import json
from sys import getsizeof
import os.path
from hashlib import blake2b

import networkx as nx
from networkx.algorithms.components import weakly_connected_components
from networkx.readwrite.json_graph import node_link_data
from flask import Blueprint, render_template, abort, jsonify, url_for, current_app
from flask_paginate import Pagination
from pkg_resources import resource_stream


cc = Blueprint("cc", __name__, url_prefix="/cc")

cc_names = []
cc_data = {}
cc_graphs = []
cc_map = {}
cc_sfrs = {}
cc_sars = {}


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
        cc_graph.add_node(value["hashid"], certid=key, href=url_for("cc.entry", hashid=value["hashid"]))
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
    mem_taken = getsizeof(cc_names) + getsizeof(cc_data) + getsizeof(cc_graphs) + getsizeof(cc_sfrs) + getsizeof(cc_sars)
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
    return render_template("cc/index.html.jinja2", certs=cc_names[(page-1)*per_page:page*per_page],
                           pagination=pagination, title=f"Common Criteria ({page}) | seccerts.org")


@cc.route("/network/")
def network():
    nodes = []
    edges = []
    for graph in cc_graphs:
        link_data = node_link_data(graph)
        nodes.extend(link_data["nodes"])
        edges.extend(link_data["links"])
    network = {
        "nodes": nodes,
        "links": edges
    }
    return render_template("cc/network.html.jinja2", network=network, title="Common Criteria network | seccerts.org")


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
