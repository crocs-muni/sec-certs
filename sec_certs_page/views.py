from datetime import datetime

from flask import abort, jsonify, make_response, render_template, request, url_for
from flask_breadcrumbs import register_breadcrumb
from werkzeug.exceptions import HTTPException

from . import app, mongo, sitemap


@app.route("/")
@register_breadcrumb(app, ".", "Home")
def index():
    return render_template("index.html.jinja2")



# @app.route("/about/")
# @register_breadcrumb(app, ".about", "About")
# def about():
#     return render_template("about.html.jinja2")


# @app.route("/changelog/")
# @register_breadcrumb(app, ".changelog", "Changelog")
# def changelog():
#     return render_template("changelog.html.jinja2")


@app.route("/robots.txt")
def robots():
    content = f"""
Sitemap: {url_for('flask_sitemap.sitemap', _external=True)}

User-agent: ClaudeBot
Crawl-delay: 10
"""
    resp = make_response(content, 200)
    resp.mimetype = "text/plain"
    return resp


@app.errorhandler(HTTPException)
def error(e):
    return (
        render_template("common/error.html.jinja2", code=e.code, name=e.name, description=e.description),
        e.code,
    )


@sitemap.register_generator
def sitemap_urls():
    yield "index", {}, None, None, 1.0
    yield "about", {}, None, None, 0.9
    yield "changelog", {}, None, None, 0.8
