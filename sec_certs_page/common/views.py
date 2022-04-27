import random
from functools import partial, wraps
from itertools import product
from pathlib import Path
from typing import Any, Dict, List, Tuple

import networkx as nx
import requests
import sentry_sdk
from flask import Response, abort, current_app, jsonify, make_response, request, send_file
from flask_paginate import Pagination as FlaskPagination
from networkx import DiGraph, node_link_data, weakly_connected_components
from werkzeug.exceptions import BadRequest

from .. import mongo


def entry_file_path(hashid, dataset_path, document, format) -> Path:
    return Path(current_app.instance_path) / dataset_path / document / format / f"{hashid}.{format}"


def _entry_download_func(collection, hashid, dataset_path, document, format) -> Response:
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        doc = mongo.db[collection].find_one({"_id": hashid})
    if doc:
        file_path = entry_file_path(hashid, dataset_path, document, format)
        if file_path.exists():
            return send_file(file_path)
    abort(404)


entry_download_report_pdf = partial(_entry_download_func, document="report", format="pdf")
entry_download_report_txt = partial(_entry_download_func, document="report", format="txt")
entry_download_target_pdf = partial(_entry_download_func, document="target", format="pdf")
entry_download_target_txt = partial(_entry_download_func, document="target", format="txt")


def entry_download_files(hashid, dataset_path, documents=("report", "target"), formats=("pdf", "txt")):
    return {
        (document, format): entry_file_path(hashid, dataset_path, document, format).exists()
        for document, format in product(documents, formats)
    }


class Pagination(FlaskPagination):
    """A pagination class that allows for a custom url_callback."""

    def __init__(self, found=0, **kwargs):
        self.url_callback = kwargs.get("url_callback", None)
        super().__init__(found, **kwargs)

    def page_href(self, page):
        if self.url_callback is None:
            return super().page_href(page)
        else:
            return self.url_callback(page=page, **self.args)


def send_json_attachment(data) -> Response:
    """Send a JSON as an attachment."""
    resp = jsonify(data)
    resp.headers["Content-Disposition"] = "attachment"
    return resp


def create_graph(references) -> Tuple[DiGraph, List[DiGraph], Dict[str, Any]]:
    """Create a graph out of references."""
    graph = nx.DiGraph()
    for key, value in references.items():
        graph.add_node(
            value["hashid"],
            certid=key,
            name=value["name"],
            href=value["href"],
            type=value["type"],
            status=value["status"],
        )
    for cert_id, reference in references.items():
        for ref_id in set(reference["refs"]):
            if ref_id in references and ref_id != cert_id:
                graph.add_edge(reference["hashid"], references[ref_id]["hashid"])
    for node in graph.nodes:
        graph.nodes[node]["referenced"] = graph.degree(node) != 0
    graphs = []
    graph_map = {}
    for component in weakly_connected_components(graph):
        subgraph = graph.subgraph(component)
        graphs.append(subgraph)
        for node in subgraph:
            graph_map[str(node)] = subgraph
    return graph, graphs, graph_map


def network_graph_func(graphs) -> Response:
    """Create a randomized JSON out of graph components."""
    nodes = []
    edges = []
    for graph in graphs:
        link_data = node_link_data(graph)
        nodes.extend(link_data["nodes"])
        edges.extend(link_data["links"])
    # random.shuffle(nodes)
    network = {"nodes": nodes, "links": edges}
    return send_json_attachment(network)


def validate_captcha(req, json) -> None:
    if not request.is_json or not request.json or "captcha" not in request.json:
        if json:
            abort(make_response(jsonify({"error": "Captcha missing.", "status": "NOK"}), 400))
        else:
            raise BadRequest(description="Captcha missing.")
    resp = requests.post(
        "https://hcaptcha.com/siteverify",
        data={
            "response": req.json["captcha"],
            "secret": current_app.config["HCAPTCHA_SECRET"],
            "ip": req.remote_addr,
            "sitekey": current_app.config["HCAPTCHA_SITEKEY"],
        },
    )
    result = resp.json()
    if not result["success"]:
        if json:
            abort(make_response(jsonify({"error": "Captcha invalid.", "status": "NOK"}), 400))
        else:
            raise BadRequest(description="Captcha invalid.")


def captcha_required(json=False):
    def captcha_deco(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            validate_captcha(request, json=json)
            return f(*args, **kwargs)

        return wrapper

    return captcha_deco
