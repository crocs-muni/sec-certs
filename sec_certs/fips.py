import json
from collections import namedtuple
from sys import getsizeof
from hashlib import blake2b

from flask import Blueprint, render_template, abort, current_app, jsonify, url_for
from flask_paginate import Pagination


fips = Blueprint("fips", __name__, url_prefix="/fips")

fips_data = {}
fips_names = []

FIPSEntry = namedtuple("FIPSEntry", ("id", "name", "hashid", "status", "level", "vendor", "type"))


@fips.before_app_first_request
def load_fips_data():
    global fips_names, fips_data
    with current_app.open_instance_resource("fips.json") as f:
        loaded_fips_data = json.load(f)
    fips_data = {blake2b(key.encode(), digest_size=20).hexdigest() : value for key, value in loaded_fips_data.items()}
    fips_names = list(sorted(FIPSEntry(int(value["cert_fips_id"]), value["fips_module_name"], key, value["fips_status"],
                              value["fips_level"], value["fips_vendor"], value["fips_type"]) for key, value in fips_data.items()))
    print(" * (FIPS) Loaded certs")
    print(f" * (FIPS) Got {len(fips_data)} certificates")
    mem_taken = getsizeof(fips_data) + getsizeof(fips_names)
    print(f" * (FIPS) Size in memory: {mem_taken}B")


@fips.route("/")
@fips.route("/<int:page>/")
def index(page=1):
    per_page = 40
    pagination = Pagination(page=page, per_page=per_page, total=len(fips_names), href=url_for(".index") + "{0}/",
                            css_framework="bootstrap4", alignment="center")
    return render_template("fips/index.html.jinja2", certs=fips_names[(page-1)*per_page:page*per_page],
                           pagination=pagination, title=f"FIPS 140 ({page}) | seccerts.org")


@fips.route("/<string(length=40):hashid>/")
def entry(hashid):
    if hashid in fips_data.keys():
        cert = fips_data[hashid]
        return render_template("fips/entry.html.jinja2", cert=cert, hashid=hashid, title=cert["fips_module_name"] + " | seccerts.org")
    else:
        return abort(404)


@fips.route("/<string(length=40):hashid>/cert.json")
def entry_json(hashid):
    if hashid in fips_data.keys():
        resp = jsonify(fips_data[hashid])
        resp.headers['Content-Disposition'] = 'attachment'
        return resp
    else:
        return abort(404)
