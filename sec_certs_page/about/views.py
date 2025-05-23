

from flask import render_template
from . import about

@about.route("/")
def index():
    return render_template("about/about.html.jinja2")

@about.route("/research/")
def research():
    return render_template("about/research.html.jinja2")

@about.route("/changelog/")
def changelog():
    return render_template("about/changelog.html.jinja2")

@about.route("/privacy-policy/")
def privacyPolicy():
    return render_template("/about/privacy-policy.html.jinja2")