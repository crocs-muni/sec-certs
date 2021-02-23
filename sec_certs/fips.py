from datetime import datetime
import json
import gc
from collections import namedtuple
from sys import getsizeof
from hashlib import blake2b

from flask import Blueprint, render_template, current_app, url_for, request
from pkg_resources import resource_stream

from networkx import info as graph_info

from sec_certs.utils import Pagination, create_graph, send_json_attachment, entry_json_func, entry_graph_json_func, entry_func, \
    network_graph_func, smallest

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
    with resource_stream("sec_certs", "fips_types.json") as f:
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


@fips.app_template_global("get_fips_type")
def get_fips_type(name):
    return fips_types.get(name, None)


@fips.route("/types.json")
def types():
    return send_json_attachment(fips_types)


@fips.route("/")
@fips.route("/<int:page>/")
def index(page=1):
    per_page = current_app.config["SEARCH_ITEMS_PER_PAGE"]
    pagination = Pagination(page=page, per_page=per_page, total=len(fips_names), href=url_for(".index") + "{0}/",
                            css_framework="bootstrap4", alignment="center")
    return render_template("fips/index.html.jinja2", certs=fips_names[(page - 1) * per_page:page * per_page],
                           pagination=pagination, title=f"FIPS 140 ({page}) | seccerts.org")


@fips.route("/network/")
def network():
    return render_template("fips/network.html.jinja2", url=url_for(".network_graph"),
                           title="FIPS 140 network | seccerts.org")


@fips.route("/network/graph.json")
def network_graph():
    return network_graph_func(fips_graphs)


def select_certs(q, cat, status, sort):
    categories = fips_types.copy()
    names = fips_names

    if q is not None:
        ql = q.lower()
        names = list(filter(lambda x: ql in x.search_name, names))

    if cat is not None:
        for category in categories.values():
            if category["id"] in cat:
                category["selected"] = True
            else:
                category["selected"] = False
        names = list(filter(lambda x: categories[x.type]["selected"] if x.type in categories else False, names))
    else:
        for category in categories.values():
            category["selected"] = True

    if status is not None and status != "Any":
        names = list(filter(lambda x: status == x.status, names))

    if sort == "number":
        pass
    elif sort == "first_cert_date":
        names = list(sorted(names, key=lambda x: x.cert_dates[0] if x.cert_dates else smallest))
    elif sort == "last_cert_date":
        names = list(sorted(names, key=lambda x: x.cert_dates[-1] if x.cert_dates else smallest))
    elif sort == "sunset_date":
        names = list(sorted(names, key=lambda x: x.sunset_date if x.sunset_date else smallest))
    return names, categories


def process_search(req, callback=None):
    page = int(req.args.get("page", 1))
    q = req.args.get("q", None)
    cat = req.args.get("cat", None)
    status = req.args.get("status", "Any")
    sort = req.args.get("sort", "number")

    names, categories = select_certs(q, cat, status, sort)

    per_page = current_app.config["SEARCH_ITEMS_PER_PAGE"]
    pagination = Pagination(page=page, per_page=per_page, search=True, found=len(names), total=len(fips_names),
                            css_framework="bootstrap4", alignment="center",
                            url_callback=callback)
    return {
        "pagination": pagination,
        "certs": names[(page - 1) * per_page:page * per_page],
        "categories": categories,
        "q": q,
        "page": page,
        "status": status,
        "sort": sort
    }


@fips.route("/search/")
def search():
    res = process_search(request)
    return render_template("fips/search.html.jinja2", **res,
                           title=f"FIPS 140 [{res['q']}] ({res['page']}) | seccerts.org")


@fips.route("/search/pagination/")
def search_pagination():
    def callback(**kwargs):
        return url_for(".search", **kwargs)

    res = process_search(request, callback=callback)
    return render_template("fips/search_pagination.html.jinja2", **res)


@fips.route("/analysis/")
def analysis():
    return


@fips.route("/<string(length=20):hashid>/")
def entry(hashid):
    return entry_func(hashid, fips_data, "fips/entry.html.jinja2")


@fips.route("/<string(length=20):hashid>/graph.json")
def entry_graph_json(hashid):
    return entry_graph_json_func(hashid, fips_data, fips_map)


@fips.route("/<string(length=20):hashid>/cert.json")
def entry_json(hashid):
    return entry_json_func(hashid, fips_data)
