from datetime import datetime
from pathlib import Path

import sentry_sdk
from flag import flag
from celery import Celery, Task
from flask import Flask, render_template, request, abort, jsonify
from flask_assets import Environment as Assets
from flask_breadcrumbs import Breadcrumbs, register_breadcrumb
from flask_caching import Cache
from flask_cors import CORS
from flask_debugtoolbar import DebugToolbarExtension
from flask_pymongo import PyMongo
from flask_redis import FlaskRedis
from flask_login import LoginManager
from flask_principal import Principal, RoleNeed, Permission
from sentry_sdk.integrations.celery import CeleryIntegration
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.redis import RedisIntegration
from sentry_sdk.integrations.logging import ignore_logger
from sec_certs.config.configuration import config as tool_config

app = Flask(__name__, instance_relative_config=True)
app.config.from_pyfile("config.py", silent=True)
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True
app.jinja_env.cache = {}
app.jinja_env.autoescape = True

sentry_sdk.init(
    dsn=app.config["SENTRY_INGEST"],
    integrations=[FlaskIntegration(), CeleryIntegration(), RedisIntegration()],
    environment=app.env,
    sample_rate=app.config["SENTRY_ERROR_SAMPLE_RATE"],
    traces_sample_rate=app.config["SENTRY_TRACES_SAMPLE_RATE"]
)

ignore_logger("sec_certs.helpers")
ignore_logger("sec_certs.dataset.dataset")
ignore_logger("sec_certs.sample.certificate")

tool_config.load(Path(app.instance_path) / app.config["TOOL_SETTINGS_PATH"])

mongo = PyMongo(app)


def make_celery(app):
    class ContextTask(Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    res = Celery(
        app.import_name,
        backend=app.config['CELERY_RESULT_BACKEND'],
        broker=app.config['CELERY_BROKER_URL'],
        result_backend=app.config['CELERY_RESULT_BACKEND'],
        task_cls=ContextTask,
        timezone="Europe/Bratislava"
    )
    return res


celery = make_celery(app)

redis = FlaskRedis(app)

assets = Assets(app)

debug = DebugToolbarExtension(app)

cache = Cache(app)

cors = CORS(app, origins="")

breadcrumbs = Breadcrumbs(app)

login = LoginManager(app)
login.login_view = "admin.login"

principal = Principal(app)


@app.before_request
def set_sentry_user():
    try:
        sentry_sdk.set_user({"ip_address": request.remote_addr})
    except Exception:
        pass


@app.template_global("country_to_flag")
def to_flag(code):
    """Turn a country code to an emoji flag."""
    if code == "UK":
        code = "GB"
    return flag(code)


@app.template_global("blueprint_url_prefix")
def blueprint_prefix():
    """The url_prefix of the current blueprint."""
    return app.blueprints[request.blueprint].url_prefix


@app.template_filter("strptime")
def filter_strptime(dt, format):
    return datetime.strptime(dt, format) if dt else None


@app.template_filter("strftime")
def filter_strftime(dt_obj, format):
    if isinstance(dt_obj, datetime):
        return dt_obj.strftime(format)
    raise TypeError("Not a datetime")


@app.template_global("is_admin")
def is_admin():
    return Permission(RoleNeed('admin')).can()


from .cc import cc

app.register_blueprint(cc)
from .pp import pp

app.register_blueprint(pp)
from .fips import fips

app.register_blueprint(fips)

from .admin import admin

app.register_blueprint(admin)


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
    data["ip"] = request.remote_addr
    data["timestamp"] = datetime.now()
    data["useragent"] = request.user_agent.string
    mongo.db.feedback.insert_one(data)
    return jsonify({"status": "OK"})


@app.route("/about")
@register_breadcrumb(app, ".about", "About")
def about():
    return render_template("about.html.jinja2")
