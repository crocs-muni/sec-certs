import os
from datetime import date, datetime
from pathlib import Path

import sentry_sdk
from celery import Celery, Task
from celery.schedules import crontab
from flag import flag
from flask import Flask, request
from flask_assets import Environment as Assets
from flask_breadcrumbs import Breadcrumbs
from flask_cachecontrol import FlaskCacheControl
from flask_caching import Cache
from flask_cors import CORS
from flask_login import LoginManager
from flask_mail import Mail
from flask_principal import Permission, Principal, RoleNeed
from flask_pymongo import PyMongo
from flask_redis import FlaskRedis
from flask_sitemap import Sitemap
from flask_wtf import CSRFProtect
from public import public
from sec_certs.config.configuration import config as tool_config
from sentry_sdk.integrations.celery import CeleryIntegration
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.logging import ignore_logger
from sentry_sdk.integrations.redis import RedisIntegration

app: Flask = Flask(__name__, instance_relative_config=True)
app.config.from_pyfile("config.py", silent=True)
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True
app.jinja_env.cache = {}
app.jinja_env.autoescape = True
app.jinja_env.globals.update(zip=zip)
public(app=app)

if os.environ.get("TESTING", False):
    app.testing = True

if not app.testing:  # pragma: no cover
    sentry_sdk.init(
        dsn=app.config["SENTRY_INGEST"],
        integrations=[FlaskIntegration(), CeleryIntegration(), RedisIntegration()],
        environment=app.env,
        sample_rate=app.config["SENTRY_ERROR_SAMPLE_RATE"],
        traces_sample_rate=app.config["SENTRY_TRACES_SAMPLE_RATE"],
    )

    ignore_logger("sec_certs.helpers")
    ignore_logger("sec_certs.dataset.dataset")
    ignore_logger("sec_certs.sample.certificate")

tool_config.load(Path(app.instance_path) / app.config["TOOL_SETTINGS_PATH"])

mongo: PyMongo = PyMongo(app)
public(mongo=mongo)


def make_celery(app):
    class ContextTask(Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    res = Celery(
        app.import_name,
        backend=app.config["CELERY_RESULT_BACKEND"],
        broker=app.config["CELERY_BROKER_URL"],
        result_backend=app.config["CELERY_RESULT_BACKEND"],
        task_cls=ContextTask,
        timezone="Europe/Bratislava",
    )
    return res


login: LoginManager = LoginManager(app)
login.login_view = "admin.login"
public(login=login)

principal: Principal = Principal(app)
public(principal=principal)

celery: Celery = make_celery(app)
public(celery=celery)

redis: FlaskRedis = FlaskRedis(app)
public(redis=redis)

assets: Assets = Assets(app)
public(assets=assets)

# debug = DebugToolbarExtension(app)

cache: Cache = Cache(app)
public(cache=cache)

cached: FlaskCacheControl = FlaskCacheControl(app)
public(cached=cached)

cors: CORS = CORS(app, origins="")
public(cors=cors)

csrf: CSRFProtect = CSRFProtect(app)
public(csrf=csrf)

mail: Mail = Mail(app)
public(mail=mail)

breadcrumbs: Breadcrumbs = Breadcrumbs(app)
public(breadcrumbs=breadcrumbs)

sitemap: Sitemap = Sitemap(app)
public(sitemap=sitemap)


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
    if isinstance(dt, str):
        return datetime.strptime(dt, format)
    if isinstance(dt, (date, datetime)):
        return dt
    return None


@app.template_filter("strftime")
def filter_strftime(dt_obj, format):
    if isinstance(dt_obj, datetime):
        return dt_obj.strftime(format)
    elif isinstance(dt_obj, date):
        return dt_obj.strftime(format)
    raise TypeError("Not a datetime or a date")


@app.template_filter("fromisoformat")
def filter_fromisoformat(dt):
    try:
        return datetime.fromisoformat(dt)
    except ValueError:
        return date.fromisoformat(dt)


@app.template_global("is_admin")
def is_admin():
    return Permission(RoleNeed("admin")).can()


from .admin import admin
from .cc import cc
from .fips import fips
from .notifications import notifications
from .pp import pp

app.register_blueprint(admin)
app.register_blueprint(cc)
app.register_blueprint(fips)
app.register_blueprint(notifications)
app.register_blueprint(pp)

from .tasks import run_updates
from .views import *


@celery.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    if app.config["UPDATE_TASK_SCHEDULE"]:
        sender.add_periodic_task(
            crontab(*app.config["UPDATE_TASK_SCHEDULE"]),
            run_updates.s(),
            name="Update data.",
        )
