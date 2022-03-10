from datetime import datetime

from flask import abort, jsonify, render_template, request, url_for, make_response
from flask_breadcrumbs import register_breadcrumb
from werkzeug.exceptions import HTTPException

from . import app, mongo, sitemap


@app.route("/")
@register_breadcrumb(app, ".", "Home")
def index():
    return render_template("index.html.jinja2")


@app.route("/feedback/", methods=["POST"])
def feedback():
    """Collect feedback from users."""
    data = request.json
    if set(data.keys()) != {"element", "comment", "path"}:
        return abort(400)
    for key in ("element", "comment", "path"):
        # TODO Add validation to client (or info abut feedback length).
        if not isinstance(data[key], str) or len(data[key]) > 256:
            return abort(400)
    # TODO add captcha
    data["ip"] = request.remote_addr
    data["timestamp"] = datetime.now()
    data["useragent"] = request.user_agent.string
    mongo.db.feedback.insert_one(data)
    return jsonify({"status": "OK"})


@app.route("/about/")
@register_breadcrumb(app, ".about", "About")
def about():
    return render_template("about.html.jinja2")


@app.route("/robots.txt")
def robots():
    content = f"Sitemap: {url_for('flask_sitemap.sitemap', _external=True)}"
    resp = make_response(content, 200)
    resp.mimetype = "text/plain"
    return resp


@app.errorhandler(HTTPException)
def error(e):
    return (
        render_template("error.html.jinja2", code=e.code, name=e.name, description=e.description),
        e.code,
    )


@sitemap.register_generator
def sitemap_urls():
    yield "index", {}
    yield "about", {}
