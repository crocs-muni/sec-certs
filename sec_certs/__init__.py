import os
import click
import json

from flag import flag
from flask import Flask, render_template, abort
from flask.cli import with_appcontext


def create_app():
	app = Flask(__name__, instance_relative_config=True)
	app.config.from_pyfile('config.py', silent=True)
	# ensure the instance folder exists
	try:
		os.makedirs(app.instance_path)
	except OSError:
		pass

	with open("certificate_data_complete.json") as f:
		cc_data = json.load(f)
	
	@app.template_global("country_to_flag")
	def to_flag(code):
		return flag(code)

	@app.route("/")
	def index():
		return render_template("index.html.jinja2")

	@app.route("/cc/")
	@app.route("/cc/<path>/")
	def cc(path=None):
		if path is None:
			return render_template("cc/index.html.jinja2", certs=cc_data.keys())
		if path in cc_data.keys():
			return render_template("cc/entry.html.jinja2", cert=cc_data[path], name=path)
		else:
			return abort(404)

	return app


