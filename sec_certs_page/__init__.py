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
from dramatiq.results.backends import StubBackend
from dramatiq.results.backends.redis import RedisBackend
from fakeredis import FakeRedis
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

if instance_path := os.environ.get("INSTANCE_PATH", None):
    instance_path = instance_path.replace("%pkg%", str(Path(__file__).absolute().parent))
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
login.login_view = "user.login"
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

redis: FlaskRedis
if app.testing:
    redis = FlaskRedis.from_custom_provider(FakeRedis, app)
else:
    redis = FlaskRedis(app)
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

from .about import about as about_bp
from .admin import admin as admin_bp
from .cc import cc as cc_bp
from .chat import chat as chat_bp
from .docs import docs as docs_bp
from .fips import fips as fips_bp
from .notifications import notifications as notifications_bp
from .pp import pp as pp_bp
from .user import user as user_bp
from .vuln import vuln as vuln_bp

with app.app_context():
    app.register_blueprint(admin_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(cc_bp)
    app.register_blueprint(fips_bp)
    app.register_blueprint(notifications_bp)
    app.register_blueprint(pp_bp)
    app.register_blueprint(vuln_bp)
    app.register_blueprint(docs_bp)
    app.register_blueprint(about_bp)
    app.register_blueprint(chat_bp)

    # Setup GitHub OAuth if enabled and configured
    if app.config.get("GITHUB_OAUTH_ENABLED", False):
        from flask_dance.contrib.github import make_github_blueprint

        if app.config.get("GITHUB_OAUTH_CLIENT_ID") and app.config.get("GITHUB_OAUTH_CLIENT_SECRET"):
            github_bp = make_github_blueprint(
                client_id=app.config["GITHUB_OAUTH_CLIENT_ID"],
                client_secret=app.config["GITHUB_OAUTH_CLIENT_SECRET"],
                scope="user:email",
                redirect_to="user.github_callback",
            )
            app.register_blueprint(github_bp, url_prefix="/auth")

from .jinja import *
from .tasks import *
from .views import *

with app.app_context():
    url_base_pathname = "/dashboard/"
    dash_app = Dash(
        __name__,
        server=app,
        url_base_pathname=url_base_pathname,
        use_pages=True,
        suppress_callback_exceptions=True,
        pages_folder="",
    )
    from .dashboard import init_dashboard

    init_dashboard(dash_app)

    def _exempt_all_dash_endpoints(app: Flask, csrf: CSRFProtect, url_base_pathname: str) -> None:
        """Dash is not using CSRF protection, so we need to exempt its routes."""
        for rule in app.url_map.iter_rules():
            if rule.rule.startswith(url_base_pathname):
                view_func = app.view_functions.get(rule.endpoint)
                if view_func is not None:
                    csrf.exempt(view_func)

    _exempt_all_dash_endpoints(app, csrf, url_base_pathname)
