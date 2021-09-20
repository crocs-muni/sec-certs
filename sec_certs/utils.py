import random
from functools import total_ordering
from typing import Any, Union

import networkx as nx
from flask import jsonify, Response
from flask_paginate import Pagination as FlaskPagination
from networkx import node_link_data, DiGraph
from networkx.algorithms.components import weakly_connected_components


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


@total_ordering
class Smallest(object):
    """An object that is smaller than everything else (except itself)."""
    def __lt__(self, other):
        if isinstance(other, Smallest):
            return False
        else:
            return True

    def __eq__(self, other):
        if isinstance(other, Smallest):
            return True
        else:
            return False


smallest = Smallest()


@total_ordering
class Biggest(object):
    """An object that is bigger than everything else (except itself)."""
    def __gt__(self, other):
        if isinstance(other, Biggest):
            return False
        else:
            return True

    def __eq__(self, other):
        if isinstance(other, Biggest):
            return True
        else:
            return False


biggest = Biggest()


def send_json_attachment(data) -> Response:
    """Send a JSON as an attachment."""
    resp = jsonify(data)
    resp.headers['Content-Disposition'] = 'attachment'
    return resp


def create_graph(references) -> tuple[DiGraph, list[DiGraph], dict[str, Any]]:
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
