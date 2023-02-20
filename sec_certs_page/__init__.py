import os
import subprocess
import time
from datetime import date, datetime
from pathlib import Path

import sentry_sdk
from celery import Celery, Task
from celery.schedules import crontab
from celery.signals import worker_process_init
from flag import flag
from flask import Flask, request
from flask_assets import Environment as Assets
from flask_breadcrumbs import Breadcrumbs
from flask_caching import Cache
from flask_cors import CORS
from flask_debugtoolbar import DebugToolbarExtension
from flask_login import LoginManager
from flask_mail import Mail
from flask_principal import Permission, Principal, RoleNeed
from flask_pymongo import PyMongo
from flask_redis import FlaskRedis
from flask_sitemap import Sitemap as FlaskSitemap
from flask_wtf import CSRFProtect
from public import public
from sec_certs.config.configuration import config as tool_config
from sec_certs.utils.extract import flatten_matches as dict_flatten
from sentry_sdk.integrations.celery import CeleryIntegration
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.logging import ignore_logger
from sentry_sdk.integrations.redis import RedisIntegration
from sentry_sdk.utils import get_default_release
from whoosh.index import EmptyIndexError, Index

from .common.search import create_index, get_index

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

    ignore_logger("sec_certs.*")

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

debug = DebugToolbarExtension(app)

cache: Cache = Cache(app)
public(cache=cache)

cors: CORS = CORS(app, origins="")
public(cors=cors)

csrf: CSRFProtect = CSRFProtect(app)
public(csrf=csrf)

mail: Mail = Mail(app)
public(mail=mail)

breadcrumbs: Breadcrumbs = Breadcrumbs(app)
public(breadcrumbs=breadcrumbs)


class Sitemap(FlaskSitemap):
    @cache.cached(timeout=3600)
    def sitemap(self):
        return super().sitemap()

    @cache.cached(timeout=3600)
    def page(self, page):
        return super().page(page)


sitemap: Sitemap = Sitemap(app)
public(sitemap=sitemap)

whoosh_index: Index
with app.app_context():
    try:
        whoosh_index = get_index()
    except EmptyIndexError:
        whoosh_index = create_index()
public(whoosh_index=whoosh_index)


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


@app.template_filter("ctime")
def filter_ctime(s):
    return time.ctime(s)


@app.template_global("flatten")
def flatten(d):
    return dict_flatten(d)


@app.template_global("is_admin")
def is_admin():
    return Permission(RoleNeed("admin")).can()


release = get_default_release()


@app.template_global()
def get_release():
    return release


from .admin import admin
from .cc import cc
from .docs import docs
from .fips import fips
from .notifications import notifications
from .pp import pp
from .vuln import vuln

with app.app_context():
    app.register_blueprint(admin)
    app.register_blueprint(cc)
    app.register_blueprint(fips)
    app.register_blueprint(notifications)
    app.register_blueprint(pp)
    app.register_blueprint(vuln)
    app.register_blueprint(docs)

from .tasks import run_updates_daily, run_updates_weekly
from .views import *


@worker_process_init.connect
def setup_celery_worker(sender, **kwargs):
    # Make sure that celery workers have their own MongoDB connection.
    mongo.init_app(app)


@celery.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    sender.add_periodic_task(
        crontab(minute=0, hour=12),
        run_updates_daily.s(),
        name="Update data (daily).",
    )
    sender.add_periodic_task(
        crontab(minute=0, hour=0, day_of_week="sun"),
        run_updates_weekly.s(),
        name="Update data (weekly).",
    )
