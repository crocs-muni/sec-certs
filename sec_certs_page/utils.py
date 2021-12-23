import hashlib
import random
from binascii import unhexlify
from datetime import date
from functools import wraps
from pathlib import Path
from typing import Any, Dict, List, Tuple, Union

import networkx as nx
import requests
from flask import Response, current_app, jsonify, make_response, request
from flask_paginate import Pagination as FlaskPagination
from networkx import DiGraph, node_link_data
from networkx.algorithms.components import weakly_connected_components
from sec_certs.sample.common_criteria import CommonCriteriaCert
from sec_certs.serialization.json import ComplexSerializableType
from werkzeug.exceptions import BadRequest, abort


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
    resp.headers['Content-Disposition'] = 'attachment'
    return resp


def create_graph(references) -> Tuple[DiGraph, List[DiGraph], Dict[str, Any]]:
    """Create a graph out of references."""
    graph = nx.DiGraph()
    for key, value in references.items():
        graph.add_node(value["hashid"], certid=key, name=value["name"], href=value["href"], type=value["type"])
    for cert_id, reference in references.items():
        for ref_id in set(reference["refs"]):
            if ref_id in references and ref_id != cert_id:
                graph.add_edge(reference["hashid"], references[ref_id]["hashid"])
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
    random.shuffle(nodes)
    network = {
        "nodes": nodes,
        "links": edges
    }
    return send_json_attachment(network)


def remove_dots(data: Union[dict, list]) -> Union[dict, list]:
    """
    Recursively replace the dots with `\uff0e` in the keys of the `data`.
    Needed because MongoDB cannot handle dots in dict keys.
    """
    if isinstance(data, dict):
        ks = list(data.keys())
        for key in ks:
            data[key] = remove_dots(data[key])
            if '.' in key:
                data[key.replace('.', '\uff0e')] = data[key]
                del data[key]
    elif isinstance(data, list):
        data = list(map(remove_dots, data))
    return data


def add_dots(data):
    """
    Recursively replace `\uff0e` dots with dots in the keys of the `data`.
    Needed because MongoDB cannot handle dots in dict keys.
    """
    if isinstance(data, dict):
        ks = list(data.keys())
        for key in ks:
            data[key] = add_dots(data[key])
            if '\uff0e' in key:
                data[key.replace('\uff0e', '.')] = data[key]
                del data[key]
    elif isinstance(data, list):
        data = list(map(add_dots, data))
    return data


def dictify_cert(cert: CommonCriteriaCert) -> dict:
    def walk(obj):
        if isinstance(obj, dict):
            return {key: walk(value) for key, value in obj.items()}
        elif isinstance(obj, (set, frozenset)):
            return [walk(o) for o in sorted(obj)]
        elif isinstance(obj, list):
            return [walk(o) for o in obj]
        elif isinstance(obj, (date, Path)):
            return str(obj)
        elif isinstance(obj, ComplexSerializableType):
            return walk(obj.to_dict())
        else:
            return obj
    cert_data = walk(cert)
    cert_data["_id"] = cert_data["dgst"]
    return remove_dots(cert_data)


def validate_captcha(req, json):
    if "captcha" not in request.json:
        if json:
            abort(make_response(jsonify({"error": "Captcha missing.", "status": "NOK"}), 400))
        else:
            raise BadRequest(description="Captcha missing.")
    resp = requests.post("https://hcaptcha.com/siteverify",
                         data={"response": req.json["captcha"],
                               "secret": current_app.config["HCAPTCHA_SECRET"],
                               "ip": req.remote_addr,
                               "sitekey": current_app.config["HCAPTCHA_SITEKEY"]})
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


def derive_secret(*items: str, digest_size: int = 16) -> bytes:
    blake = hashlib.blake2b(b"".join(map(lambda x: x.encode("utf-8"), items)),
                            key=unhexlify(current_app.config["SECRET_KEY"]),
                            digest_size=digest_size)
    return blake.digest()


def derive_token(*items: str, digest_size: int = 16) -> str:
    secret = derive_secret(*items, digest_size=digest_size)
    return secret.hex()
