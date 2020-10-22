from flask import Blueprint, render_template, abort

pp = Blueprint("pp", __name__, url_prefix="/pp")

@pp.route("/")
def index():
	return render_template("pp/index.html.jinja2", title="Protection Profiles | seccerts.org")

@pp.route("/<string(length=40):hashid>/")
def entry(hashid):
	return abort(404)
