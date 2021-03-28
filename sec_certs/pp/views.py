import sentry_sdk
from flask import render_template, abort

from . import pp
from .. import mongo
from ..utils import add_dots


@pp.route("/")
def index():
    return render_template("pp/index.html.jinja2", title="Protection Profiles | seccerts.org")


@pp.route("/<string(length=20):hashid>/")
def entry(hashid):
    with sentry_sdk.start_span(op="mongo", description="Find profile"):
        doc = mongo.db.pp.find_one({"_id": hashid})
    if doc:
        return render_template("pp/entry.html.jinja2", profile=add_dots(doc), hashid=hashid)
    else:
        return abort(404)
