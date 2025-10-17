from datetime import datetime, timezone
from functools import partial, wraps
from itertools import product
from pathlib import Path
from typing import Any, Dict, List, Literal, Tuple

import flask
import networkx as nx
import pendulum
import requests
import sentry_sdk
from flask import Response, abort, current_app, jsonify, make_response, request, send_file
from flask_login import current_user
from flask_paginate import Pagination as FlaskPagination
from networkx import DiGraph, node_link_data, weakly_connected_components
from werkzeug.exceptions import BadRequest

from .. import mongo


def entry_file_path_relative(root, hashid, dataset_path, document, format) -> Path:
    return root / dataset_path / document / format / f"{hashid}.{format}"


def entry_file_path(hashid, dataset_path, document, format) -> Path:
    return entry_file_path_relative(Path(current_app.instance_path), hashid, dataset_path, document, format)


def _entry_download_func(collection, hashid, dataset_path, document, format) -> Response:
    with sentry_sdk.start_span(op="mongo", description="Find cert"):
        doc = mongo.db[collection].find_one({"_id": hashid})
    if doc:
        file_path = entry_file_path(hashid, dataset_path, document, format)
        if file_path.exists():
            if current_app.config["USE_X_ACCEL_REDIRECT"]:
                response = make_response()
                response.content_type = {"txt": "text/plain", "pdf": "application/pdf"}[format]
                response.headers["X-Accel-Redirect"] = entry_file_path_relative(
                    Path(current_app.config["X_ACCEL_REDIRECT_PATH"]), hashid, dataset_path, document, format
                )
                return response
            else:
                return send_file(file_path)
    return abort(404)


entry_download_report_pdf = partial(_entry_download_func, document="report", format="pdf")
entry_download_report_txt = partial(_entry_download_func, document="report", format="txt")
entry_download_target_pdf = partial(_entry_download_func, document="target", format="pdf")
entry_download_target_txt = partial(_entry_download_func, document="target", format="txt")
entry_download_certificate_pdf = partial(_entry_download_func, document="cert", format="pdf")
entry_download_certificate_txt = partial(_entry_download_func, document="cert", format="txt")
entry_download_profile_pdf = partial(_entry_download_func, document="profile", format="pdf")
entry_download_profile_txt = partial(_entry_download_func, document="profile", format="txt")


def entry_download_files(
    hashid, dataset_path, documents=("report", "target", "cert", "profile"), formats=("pdf", "txt")
):
    return {
        (document, format): entry_file_path(hashid, dataset_path, document, format).exists()
        for document, format in product(documents, formats)
    }


def expires_at(when):
    def after_response(response):
        now = pendulum.now()
        next_run = when.next_valid_date(now)
        response.expires = next_run
        return response

    def deco(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            flask.after_this_request(after_response)
            return f(*args, **kwargs)

        return wrapper

    return deco


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
    resp.cache_control.no_cache = True
    return resp


def send_cacheable_instance_file(path: str, mimetype: str, download_name: str) -> Response:
    full_path = Path(current_app.instance_path) / path
    if not full_path.is_file():
        return abort(404)
    if current_app.config["USE_X_ACCEL_REDIRECT"]:
        response = make_response()
        response.content_type = mimetype
        response.headers["Content-Disposition"] = f"attachment; filename={download_name}"
        response.headers["X-Accel-Redirect"] = Path(current_app.config["X_ACCEL_REDIRECT_PATH"]) / path
    else:
        response = send_file(full_path, as_attachment=True, mimetype=mimetype, download_name=download_name)
    response.cache_control.no_cache = None
    response.cache_control.no_transform = True
    return response


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
            vuln=value["vuln"],
        )
    for cert_id, reference in references.items():
        for ref_type, refs in reference["refs"].items():
            for ref_id in set(refs):
                if ref_id in references and ref_id != cert_id:
                    edge = (reference["hashid"], references[ref_id]["hashid"])
                    if edge in graph.edges:
                        graph.edges[edge]["type"].append(ref_type)
                    else:
                        graph.add_edge(*edge, type=[ref_type])
    for node in graph.nodes:
        graph.nodes[node]["referenced"] = graph.degree(node) != 0
    graphs = []
    graph_map = {}
    for component in weakly_connected_components(graph):
        subgraph = graph.subgraph(component).copy()
        graphs.append(subgraph)
        for node in subgraph:
            graph_map[str(node)] = subgraph
    return graph, graphs, graph_map


def network_graph_func(graphs, highlighted=None) -> Response:
    """Create a JSON out of graph components."""
    nodes = []
    edges = []
    for graph in graphs:
        link_data = node_link_data(graph, edges="links")
        nodes.extend(link_data["nodes"])
        edges.extend(link_data["links"])
    network = {"nodes": nodes, "links": edges, "highlighted": highlighted}
    return send_json_attachment(network)


def validate_captcha(req, json) -> None:  # pragma: no cover
    if not request.is_json or not request.json or "captcha" not in request.json:
        if json:
            abort(make_response(jsonify({"error": "Captcha missing.", "status": "NOK"}), 400))
        else:
            raise BadRequest(description="Captcha missing.")
    resp = requests.post(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data={
            "response": req.json["captcha"],
            "secret": current_app.config["TURNSTILE_SECRET"],
            "remoteip": req.remote_addr,
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


def register_breadcrumb(app, path, text, order=0, endpoint_arguments_constructor=None, dynamic_list_constructor=None):
    # Return a decorator that does nothing
    def breadcrumb_decorator(func):
        """Apply standard menu decorator and assign breadcrumb."""
        func.__breadcrumb__ = path
        return func

    return breadcrumb_decorator


def sitemap_cert_pipeline(collection: str):
    return [
        {"$lookup": {"from": f"{collection}_diff", "localField": "_id", "foreignField": "dgst", "as": "joined_docs"}},
        {"$unwind": "$joined_docs"},
        {"$sort": {"joined_docs.timestamp": -1}},
        {"$group": {"_id": "$_id", "latest_joined_doc": {"$first": "$joined_docs"}}},
        {"$project": {"_id": 1, "timestamp": "$latest_joined_doc.timestamp"}},
    ]


def accounting(
    aggregate: Literal["daily"] | Literal["monthly"] | Literal[None] = "daily",
    limit: int | None = None,
    json: bool = True,
):
    """A decorator to store accounting information about requests.

    :param aggregate: The aggregation period ("daily", monthly", or None).
    :param limit: The maximum number of requests allowed in the aggregation period.
    :param json: Whether to return JSON responses on limit exceeded.
    """

    def deco(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = datetime.now(timezone.utc)
            if aggregate == "daily":
                period = now.replace(hour=0, minute=0, second=0, microsecond=0)
            elif aggregate == "monthly":
                period = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            else:
                period = None
            doc: dict[str, Any] = (
                {"username": current_user.username} if current_user.is_authenticated else {"ip": request.remote_addr}
            )
            doc["endpoint"] = request.endpoint
            doc["period"] = period
            present = mongo.db.accounting.find_one(doc)
            if present:
                if limit is not None:
                    if present.get("count", 0) < limit:
                        mongo.db.accounting.update_one(doc, {"$inc": {"count": 1}})
                    else:
                        message = f"You have reached the request limit of {limit} requests {aggregate} ({period})."
                        if json:
                            return jsonify({"status": "error", "message": message}), 429
                        else:
                            return abort(429, description=message)
            else:
                doc["count"] = 1
                r = mongo.db.accounting.insert_one(doc)
            res = func(*args, **kwargs)

            return res

        return wrapper

    return deco
