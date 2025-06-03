from datetime import datetime

from flask import make_response, render_template, url_for
from werkzeug.exceptions import HTTPException

from . import app, sitemap
from .common.views import register_breadcrumb


@app.route("/")
@register_breadcrumb(app, ".", "Home")
def index():
    return render_template("index.html.jinja2")


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
    yield "about.index", {}, None, None, 0.9
    yield "about.changelog", {}, None, None, 0.8
    yield "about.research", {}, None, None, 0.8
    yield "about.privacy_policy", {}, None, None, 0.8
