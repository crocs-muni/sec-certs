import os
import sys
from contextvars import ContextVar
from pathlib import Path

import sentry_sdk
from dramatiq import Middleware
from dramatiq.middleware import (
    AgeLimit,
    Callbacks,
    CurrentMessage,
    Pipelines,
    Retries,
    ShutdownNotifications,
    TimeLimit,
)
from dramatiq.results import Results
from dramatiq.results.backends import RedisBackend, StubBackend
from flask import Flask, abort
from flask_assets import Environment as Assets
from flask_caching import Cache
from flask_cors import CORS
from flask_debugtoolbar import DebugToolbarExtension
from flask_login import LoginManager
from flask_mail import Mail
from flask_melodramatiq import Broker, RedisBroker, StubBroker
from flask_principal import Principal
from flask_pymongo import PyMongo
from flask_redis import FlaskRedis
from flask_sitemap import Sitemap as FlaskSitemap
from flask_wtf import CSRFProtect
from periodiq import PeriodiqMiddleware
from public import public
from sec_certs.configuration import config as tool_config
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.logging import ignore_logger
from sentry_sdk.integrations.redis import RedisIntegration
from whoosh.index import EmptyIndexError, Index

from .common.config import RuntimeConfig
from .common.dash.base import Dash
from .common.search.index import create_index, get_index
from .common.sentry import DramatiqIntegration, before_send

# See https://github.com/crocs-muni/sec-certs/issues/470
sys.setrecursionlimit(8000)

instance_path = os.environ.get("INSTANCE_PATH", None)
app: Flask = Flask(__name__, instance_path=instance_path, instance_relative_config=True)
app.config.from_pyfile("config.py", silent=True)
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True
app.jinja_env.cache = {}
app.jinja_env.autoescape = True
app.jinja_env.globals.update(zip=zip)
public(app=app)

if os.environ.get("TESTING", False):
    app.testing = True
    del app.config["DRAMATIQ_BROKER_URL"]
    app.config["DEBUG_TB_ENABLED"] = False
    app.config["DEBUG_TB_INTERCEPT_REDIRECTS"] = False

if not app.testing and app.config["SENTRY_INGEST"]:  # pragma: no cover
    sentry_sdk.init(
        dsn=app.config["SENTRY_INGEST"],
        integrations=[FlaskIntegration(), RedisIntegration(), DramatiqIntegration()],
        before_send=before_send,
        environment=app.config["SENTRY_ENV"],
        sample_rate=app.config["SENTRY_ERROR_SAMPLE_RATE"],
        traces_sample_rate=app.config["SENTRY_TRACES_SAMPLE_RATE"],
        send_default_pii=True,
        enable_tracing=True,
    )

    ignore_logger("sec_certs.*")

tool_config.load_from_yaml(Path(app.instance_path) / app.config["TOOL_SETTINGS_PATH"])

mongo: PyMongo = PyMongo(app)
public(mongo=mongo)

login: LoginManager = LoginManager(app)
login.login_view = "admin.login"
public(login=login)

principal: Principal = Principal(app)
public(principal=principal)


class MongoMiddleware(Middleware):
    def after_worker_boot(self, broker, worker):
        # Make sure that workers have their own MongoDB connection.
        mongo.init_app(app)


broker_middleware = [
    AgeLimit(),
    TimeLimit(time_limit=60 * 1000 * 30),
    ShutdownNotifications(),
    CurrentMessage(),
    Callbacks(),
    Pipelines(),
    Retries(),
    PeriodiqMiddleware(),
    MongoMiddleware(),
    Results(backend=RedisBackend(url=app.config["DRAMATIQ_BROKER_URL"]) if not app.testing else StubBackend()),
]
broker: Broker = (
    RedisBroker(app, middleware=broker_middleware) if not app.testing else StubBroker(app, middleware=broker_middleware)
)
broker.set_default()
public(broker=broker)

redis: FlaskRedis = FlaskRedis(app)
public(redis=redis)

runtime_config: RuntimeConfig = RuntimeConfig(app)
public(runtime_config=runtime_config)

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

dash: Dash = Dash(server=app, routes_pathname_prefix="/dash/", use_pages=True, pages_folder="")
public(dash=dash)
# This Dash view uses a POST and CSRFProtect is messing it up otherwise.
csrf.exempt("dash.dash.dispatch")


class Sitemap(FlaskSitemap):
    @cache.memoize(args_to_ignore=("self",), timeout=3600 * 24 * 7)
    def sitemap(self):
        return super().sitemap()

    @cache.memoize(args_to_ignore=("self",), timeout=3600 * 24 * 7)
    def page(self, page):
        if page < 1:
            return abort(404)
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

whoosh_searcher: ContextVar = ContextVar("whoosh_searcher")


def get_searcher():
    try:
        searcher = whoosh_searcher.get()
        searcher = searcher.refresh()
    except LookupError:
        searcher = whoosh_index.searcher()
    whoosh_searcher.set(searcher)
    return searcher


public(whoosh_searcher=whoosh_searcher)

from .about import about
from .admin import admin
from .cc import cc
from .chat import chat
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
    app.register_blueprint(about)
    app.register_blueprint(chat)

from .dash import *
from .jinja import *
from .tasks import *
from .views import *
