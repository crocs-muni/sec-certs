import json
import gc
from collections import namedtuple
import random
from sys import getsizeof
from datetime import datetime
from hashlib import blake2b

from flask import Blueprint, render_template, url_for, current_app, request, redirect
from pkg_resources import resource_stream

from networkx import info as graph_info

from sec_certs.utils import Pagination, smallest, create_graph, entry_func, entry_json_func, entry_graph_json_func, \
    network_graph_func, send_json_attachment

cc = Blueprint("cc", __name__, url_prefix="/cc")

cc_names = []
cc_data = {}
cc_graphs = []
cc_analysis = {}
cc_map = {}
cc_sfrs = {}
cc_sars = {}
cc_categories = {}

CCEntry = namedtuple("CCEntry", ("name", "hashid", "status", "cert_date", "archived_date", "category", "search_name"))


@cc.before_app_first_request
def load_cc_data():
    global cc_names, cc_data, cc_graphs, cc_map, cc_analysis, cc_sfrs, cc_sars, cc_categories
    # Load raw data
    with current_app.open_instance_resource("cc.json") as f:
        data = f.read()
        loaded_cc_data = json.loads(data)
        del data
    print(" * (CC) Loaded certs")
    with resource_stream("sec_certs", "cc_sfrs.json") as f:
        cc_sfrs = json.load(f)
    print(" * (CC) Loaded SFRs")
    with resource_stream("sec_certs", "cc_sars.json") as f:
        cc_sars = json.load(f)
    print(" * (CC) Loaded SARs")
    with resource_stream("sec_certs", "cc_categories.json") as f:
        cc_categories = json.load(f)
    print(" * (CC) Loaded categories")

    # Create ids
    cc_data = {blake2b(key.encode(), digest_size=10).hexdigest(): value for key, value in loaded_cc_data.items()}
    del loaded_cc_data
    cc_names = list(sorted(CCEntry(value["csv_scan"]["cert_item_name"], key, value["csv_scan"]["cert_status"],
                                   datetime.strptime(value["csv_scan"]["cc_certification_date"], "%m/%d/%Y"),
                                   datetime.strptime(value["csv_scan"]["cc_archived_date"], "%m/%d/%Y") if
                                   value["csv_scan"]["cc_archived_date"] else value["csv_scan"]["cc_archived_date"],
                                   value["csv_scan"]["cc_category"], value["csv_scan"]["cert_item_name"].lower())
                           for key, value in cc_data.items()))

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
            "refs": [],
            "href": url_for("cc.entry", hashid=hashid),
            "type": cc_categories[cert["csv_scan"]["cc_category"]]["id"]
        }

        if current_app.config["CC_GRAPH"] in ("BOTH", "CERT_ONLY") and "keywords_scan" in cert and \
                cert["keywords_scan"]["rules_cert_id"]:
            items = sum(map(lambda x: list(x.keys()), cert["keywords_scan"]["rules_cert_id"].values()), [])
            reference["refs"].extend(items)
        if current_app.config["CC_GRAPH"] in ("BOTH", "ST_ONLY") and "st_keywords_scan" in cert and \
                cert["st_keywords_scan"]["rules_cert_id"]:
            items = sum(map(lambda x: list(x.keys()), cert["st_keywords_scan"]["rules_cert_id"].values()), [])
            reference["refs"].extend(items)
        cc_references[cert_id] = reference

    cc_graph, cc_graphs, cc_map = create_graph(cc_references)
    print(f" * (CC) Got {len(cc_data)} certificates")
    print(f" * (CC) Got {len(cc_references)} certificates with IDs")
    print(f" * (CC) Got graph:\n{graph_info(cc_graph)}")
    print(" * (CC) Made network")
    del cc_graph

    cc_analysis["categories"] = {}
    for cert in cc_names:
        cc_analysis["categories"].setdefault(cert.category, 0)
        cc_analysis["categories"][cert.category] += 1
    cc_analysis["categories"] = [{"name": key, "value": value} for key, value in cc_analysis["categories"].items()]

    cc_analysis["certified"] = {}
    for cert in cc_names:
        cert_month = cert.cert_date.replace(day=1).strftime("%Y-%m-%d")
        cc_analysis["certified"].setdefault(cert.category, [])
        months = cc_analysis["certified"][cert.category]
        for month in months:
            if month["date"] == cert_month:
                month["value"] += 1
                break
        else:
            months.append({"date": cert_month, "value": 1})
    certified = {}
    for category, months in cc_analysis["certified"].items():
        for month in months:
            if month["date"] in certified:
                certified[month["date"]][category] = month["value"]
            else:
                certified[month["date"]] = {category: month["value"]}
    certified = [{"date": key, **value} for key, value in certified.items()]
    for category in cc_analysis["certified"].keys():
        for month in certified:
            if category not in month.keys():
                month[category] = 0
    cc_analysis["certified"] = list(sorted(certified, key=lambda x: x["date"]))
    print(" * (CC) Performed analysis")

    mem_taken = sum(map(getsizeof, (cc_names, cc_data, cc_graphs, cc_map, cc_sars, cc_sfrs, cc_categories, cc_analysis)))
    print(f" * (CC) Size in memory: {mem_taken}B")
    gc.collect()


@cc.app_template_global("get_cc_sar")
def get_cc_sar(sar):
    return cc_sars.get(sar, None)


@cc.route("/sars.json")
def sars():
    return send_json_attachment(cc_sars)


@cc.app_template_global("get_cc_sfr")
def get_cc_sfr(sfr):
    return cc_sfrs.get(sfr, None)


@cc.route("/sfrs.json")
def sfrs():
    return send_json_attachment(cc_sfrs)


@cc.app_template_global("get_cc_category")
def get_cc_category(name):
    return cc_categories.get(name, None)


@cc.route("/categories.json")
def categories():
    return send_json_attachment(cc_categories)


@cc.route("/")
def index():
    return render_template("cc/index.html.jinja2", title=f"Common Criteria | seccerts.org")


@cc.route("/network/")
def network():
    return render_template("cc/network.html.jinja2", url=url_for(".network_graph"),
                           title="Common Criteria network | seccerts.org")


@cc.route("/network/graph.json")
def network_graph():
    return network_graph_func(cc_graphs)


def select_certs(q, cat, status, sort):
    categories = cc_categories.copy()
    names = cc_names

    if q is not None:
        ql = q.lower()
        names = list(filter(lambda x: ql in x.search_name, names))

    if cat is not None:
        for category in categories.values():
            if category["id"] in cat:
                category["selected"] = True
            else:
                category["selected"] = False
        names = list(filter(lambda x: categories[x.category]["selected"], names))
    else:
        for category in categories.values():
            category["selected"] = True

    if status is not None and status != "any":
        names = list(filter(lambda x: status == x.status, names))

    if sort == "name":
        pass
    elif sort == "cert_date":
        names = list(sorted(names, key=lambda x: x.cert_date if x.cert_date else smallest))
    elif sort == "archive_date":
        names = list(sorted(names, key=lambda x: x.archived_date if x.archived_date else smallest))

    return names, categories


def process_search(req, callback=None):
    page = int(req.args.get("page", 1))
    q = req.args.get("q", None)
    cat = req.args.get("cat", None)
    status = req.args.get("status", "any")
    sort = req.args.get("sort", "name")

    names, categories = select_certs(q, cat, status, sort)

    per_page = current_app.config["SEARCH_ITEMS_PER_PAGE"]
    pagination = Pagination(page=page, per_page=per_page, search=True, found=len(names), total=len(cc_names),
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


@cc.route("/search/")
def search():
    res = process_search(request)
    return render_template("cc/search.html.jinja2", **res,
                           title=f"Common Criteria [{res['q']}] ({res['page']}) | seccerts.org")


@cc.route("/search/pagination/")
def search_pagination():
    def callback(**kwargs):
        return url_for(".search", **kwargs)

    res = process_search(request, callback=callback)
    return render_template("cc/search_pagination.html.jinja2", **res)


@cc.route("/analysis/")
def analysis():
    return render_template("cc/analysis.html.jinja2", analysis=cc_analysis)


@cc.route("/random/")
def rand():
    return redirect(url_for(".entry", hashid=random.choice(list(cc_data.keys()))))


@cc.route("/<string(length=20):hashid>/")
def entry(hashid):
    return entry_func(hashid, cc_data, "cc/entry.html.jinja2")


@cc.route("/<string(length=20):hashid>/graph.json")
def entry_graph_json(hashid):
    return entry_graph_json_func(hashid, cc_data, cc_map)


@cc.route("/<string(length=20):hashid>/cert.json")
def entry_json(hashid):
    return entry_json_func(hashid, cc_data)
