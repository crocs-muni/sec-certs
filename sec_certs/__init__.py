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
        cc_names = {key: value["csv_scan"]["cert_item_name"] for key, value in cc_data.items()}

    @app.template_global("country_to_flag")
    def to_flag(code):
        return flag(code)

    @app.route("/")
    def index():
        return render_template("index.html.jinja2")

    @app.route("/cc/")
    @app.route("/cc/<hashid>/")
    def cc(hashid=None):
        if hashid is None:
            return render_template("cc/index.html.jinja2", certs=cc_names)

        if hashid in cc_data.keys():
            return render_template("cc/entry.html.jinja2", cert=cc_data[hashid])
        else:
            return abort(404)

    return app
