import random

from flask import render_template, abort, jsonify
from flask_paginate import Pagination as FlaskPagination
from functools import total_ordering
import networkx as nx
from networkx import node_link_data
from networkx.algorithms.components import weakly_connected_components


class Pagination(FlaskPagination):
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
    def __lt__(self, other):
        return True

    def __eq__(self, other):
        if isinstance(other, Smallest):
            return True
        else:
            return False


smallest = Smallest()


@total_ordering
class Biggest(object):
    def __gt__(self, other):
        return True

    def __eq__(self, other):
        if isinstance(other, Biggest):
            return True
        else:
            return False


biggest = Biggest()


def send_json_attachment(data):
    resp = jsonify(data)
    resp.headers['Content-Disposition'] = 'attachment'
    return resp


def create_graph(references):
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


def network_graph_func(graphs):
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


def entry_func(hashid, data, template_name):
    if hashid in data.keys():
        cert = data[hashid]
        return render_template(template_name, cert=cert, hashid=hashid)
    else:
        return abort(404)


def entry_json_func(hashid, data):
    if hashid in data.keys():
        return send_json_attachment(data[hashid])
    else:
        return abort(404)


def entry_graph_json_func(hashid, data, graph_map):
    if hashid in data.keys():
        if hashid in graph_map.keys():
            graph = graph_map[hashid]
            network = node_link_data(graph)
        else:
            network = {}
        return send_json_attachment(network)
    else:
        return abort(404)


def remove_dots(data):
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
    if isinstance(data, dict):
        ks = list(data.keys())
        for key in ks:
            data[key] = remove_dots(data[key])
            if '\uff0e' in key:
                data[key.replace('\uff0e', '.')] = data[key]
                del data[key]
    elif isinstance(data, list):
        data = list(map(remove_dots, data))
    return data
