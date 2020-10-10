import json
from hashlib import blake2b

from flask import Blueprint, render_template, abort, jsonify, url_for
from flask_paginate import Pagination

cc = Blueprint("cc", __name__, url_prefix="/cc")

cc_names = None
cc_data = None
cc_network = None

@cc.before_app_first_request
def load_cc_data():
    global cc_names, cc_data, cc_network
    with open("certificate_data_complete.json") as f:
        loaded_cc_data = json.load(f)
        cc_data = {blake2b(key.encode(), digest_size=20).hexdigest() : value for key, value in loaded_cc_data.items()}
        cc_names = list(sorted((value["csv_scan"]["cert_item_name"], key, value["csv_scan"]["cert_status"], value["csv_scan"]["cc_certification_date"], value["csv_scan"]["cc_archived_date"]) for key, value in cc_data.items()))
        cc_references = {}
        for hashid, cert in cc_data.items():
            if "processed" in cert and "cert_id" in cert["processed"] and cert["processed"]["cert_id"] != "":
                cert_id = cert["processed"]["cert_id"]
            else:
                continue
            reference = {
                "hashid": hashid,
                "refs": []
            }
            if "keywords_scan" in cert and cert["keywords_scan"]["rules_cert_id"]:
                items = sum(map(lambda x: list(x.keys()), cert["keywords_scan"]["rules_cert_id"].values()), [])
                reference["refs"].extend(items)
            if "st_keywords_scan" in cert and cert["st_keywords_scan"]["rules_cert_id"]:
                items = sum(map(lambda x: list(x.keys()), cert["st_keywords_scan"]["rules_cert_id"].values()), [])
                reference["refs"].extend(items)
            cc_references[cert_id] = reference
        
        cc_nodes = [{"id": key, "hashid": value["hashid"]} for key, value in cc_references.items()]
        cc_edges = []
        cc_refd = set()
        for cert_id, reference in cc_references.items():
            for ref_id in reference["refs"]:
                if ref_id in cc_references and ref_id != cert_id:
                    cc_edges.append({"source": cert_id, "target": ref_id, "value": 1})
                    cc_refd.add(cert_id)
                    cc_refd.add(ref_id)
        cc_nodes = list(filter(lambda x: x["id"] in cc_refd, cc_nodes))
        cc_network = {
            "nodes": cc_nodes,
            "links": cc_edges
        }
        print(len(cc_nodes), len(cc_edges))

@cc.route("/")
@cc.route("/<int:page>")
def index(page=1):
    per_page = 40
    pagination = Pagination(page=page, per_page=per_page, total=len(cc_names), href=url_for(".index") + "{0}", css_framework="bootstrap4", alignment="center")
    return render_template("cc/index.html.jinja2", certs=cc_names[(page-1)*per_page:page*per_page], pagination=pagination)

@cc.route("/network")
def network():
    return render_template("cc/network.html.jinja2", network=cc_network)

@cc.route("/search")
def search():
    return render_template("cc/network.html.jinja2", network=cc_network)

@cc.route("/<string(length=40):hashid>/")
def entry(hashid):
    if hashid in cc_data.keys():
        cert = cc_data[hashid]
        return render_template("cc/entry.html.jinja2", cert=cert, hashid=hashid)
    else:
        return abort(404)

@cc.route("/<string(length=40):hashid>/cert.json")
def entry_json(hashid):
    if hashid in cc_data.keys():
        resp = jsonify(cc_data[hashid])
        resp.headers['Content-Disposition'] = 'attachment'
        return resp
    else:
        return abort(404)
