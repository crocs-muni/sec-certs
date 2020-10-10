import os
import click
import json
from hashlib import blake2b

from flag import flag
from flask import Flask, render_template, abort
from flask.cli import with_appcontext


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_pyfile("config.py", silent=True)
    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    with open("certificate_data_complete.json") as f:
        loaded_cc_data = json.load(f)
        cc_data = {blake2b(key.encode(), digest_size=20).hexdigest() : value for key, value in loaded_cc_data.items()}
        cc_names = list(sorted((value["csv_scan"]["cert_item_name"], key) for key, value in cc_data.items()))
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

    @app.template_global("country_to_flag")
    def to_flag(code):
        return flag(code)

    @app.route("/")
    def index():
        return render_template("index.html.jinja2")

    @app.route("/cc/network")
    def cc_net():
        return render_template("cc/network.html.jinja2", network=cc_network)

    @app.route("/cc/search")
    def cc_search():
        return render_template("cc/network.html.jinja2", network=cc_network)

    @app.route("/cc/")
    def cc_index():
        return render_template("cc/index.html.jinja2", certs=cc_names)

    @app.route("/cc/<string(length=40):hashid>/")
    def cc(hashid):
        if hashid in cc_data.keys():
            cert = cc_data[hashid]
            return render_template("cc/entry.html.jinja2", cert=cert)
        else:
            return abort(404)
    
    @app.route("/fips/")
    def fips_index():
        return render_template("fips/index.html.jinja2")

    @app.route("/fips/<string(length=40):hashid>/")
    def fips(hashid):
        return abort(404)

    return app
