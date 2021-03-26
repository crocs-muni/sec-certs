import random
from flask import render_template, current_app, url_for, request, redirect


from sec_certs.utils import Pagination, send_json_attachment, entry_json_func, entry_graph_json_func, entry_func, \
    network_graph_func, smallest
from . import fips, fips_data, fips_map, fips_types, fips_graphs, fips_names



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
    return render_template("fips/analysis.html.jinja2")


@fips.route("/random/")
def rand():
    return redirect(url_for(".entry", hashid=random.choice(list(fips_data.keys()))))


@fips.route("/<string(length=20):hashid>/")
def entry(hashid):
    return entry_func(hashid, fips_data, "fips/entry.html.jinja2")


@fips.route("/<string(length=20):hashid>/graph.json")
def entry_graph_json(hashid):
    return entry_graph_json_func(hashid, fips_data, fips_map)


@fips.route("/<string(length=20):hashid>/cert.json")
def entry_json(hashid):
    return entry_json_func(hashid, fips_data)
