import random

from flask import render_template, url_for, current_app, request, redirect


from sec_certs.utils import Pagination, smallest, entry_func, entry_json_func, entry_graph_json_func, \
    network_graph_func, send_json_attachment
from . import cc, cc_sars, cc_sfrs, cc_categories, cc_analysis, cc_data, cc_graphs, cc_map, cc_names



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
