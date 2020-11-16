import json

from flask import Blueprint, render_template, abort, current_app

pp = Blueprint("pp", __name__, url_prefix="/pp")

pp_data = {}


@pp.before_app_first_request
def load_pp_data():
	global pp_data
	with current_app.open_instance_resource("pp.json") as f:
		loaded_pp_data = json.load(f)
	pass

@pp.route("/")
def index():
	return render_template("pp/index.html.jinja2", title="Protection Profiles | seccerts.org")


@pp.route("/<string(length=40):hashid>/")
def entry(hashid):
	return abort(404)
