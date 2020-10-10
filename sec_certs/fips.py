from flask import Blueprint, render_template, abort

fips = Blueprint("fips", __name__, url_prefix="/fips")

@fips.route("/")
def index():
	return render_template("fips/index.html.jinja2")

@fips.route("/<string(length=40):hashid>/")
def entry(hashid):
	return abort(404)
