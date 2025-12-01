import re
import time
from datetime import date, datetime
from os.path import join

import sentry_sdk
from flag import flag
from flask import current_app, request
from flask_principal import Permission, RoleNeed
from markupsafe import Markup
from nacl.hashlib import blake2b
from sec_certs.utils.extract import flatten_matches as dict_flatten
from sentry_sdk.utils import get_default_release

from . import app, cache, runtime_config


@app.template_global("country_to_flag")
def to_flag(code):
    """Turn a country code to an emoji flag."""
    if code == "UK":
        code = "GB"
    return flag(code) if code else "❌"


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


@app.template_filter("fips_name")
def filter_fips_name(cert):
    web_data = cert.get("web_data", cert.get("web_scan"))
    if web_data:
        return web_data.get("module_name")
    return None


@app.template_test("date")
def is_date(dt_obj):
    return isinstance(dt_obj, date)


@app.template_test("datetime")
def is_datetime(dt_obj):
    return isinstance(dt_obj, datetime)


@app.template_filter("ctime")
def filter_ctime(s):
    return time.ctime(s)


@app.template_global("flatten")
def flatten(d):
    return dict_flatten(d)


@app.template_global("is_admin")
def is_admin():
    return Permission(RoleNeed("admin")).can()


@app.template_global("can_access_dashboard")
def can_access_dashboard():
    from .common.permissions import dashboard_permission

    return dashboard_permission.can()


@app.template_global("sentry_traceparent")
def sentry_traceparent():
    if sentry_sdk.is_initialized():
        return sentry_sdk.get_traceparent()
    return None


@app.template_global("sentry_baggage")
def sentry_baggage():
    if sentry_sdk.is_initialized():
        return sentry_sdk.get_baggage()
    return None


@app.template_global("endpoint")
def endpoint():
    rule = str(request.url_rule)
    return re.sub("<.*?>", "*", rule)


@app.template_global("event_navbar")
def event_navbar():
    return runtime_config.get("EVENT_NAVBAR")


@app.template_global("include_static")
@cache.memoize(timeout=3600, unless=lambda: current_app.debug)
def include_static(filename: str):
    bp = current_app.blueprints.get(request.blueprint)
    if bp is not None and bp.static_folder is not None:
        try:
            with open(join(bp.static_folder, filename), "r", encoding="utf-8") as f:
                return Markup(f.read())
        except FileNotFoundError:
            return None
    elif current_app.static_folder is not None:
        try:
            with open(join(current_app.static_folder, filename), "r", encoding="utf-8") as f:
                return Markup(f.read())
        except FileNotFoundError:
            return None
    else:
        return None


release = get_default_release()


@app.template_global()
def get_release():
    return release


@app.template_global()
@cache.memoize(timeout=0)
def static_hash(filename: str):
    """Get the hash of a static file."""
    bp = current_app.blueprints.get(request.blueprint)
    if bp is not None and bp.static_folder is not None:
        path = join(bp.static_folder, filename)
    elif current_app.static_folder is not None:
        path = join(current_app.static_folder, filename)
    else:
        return None

    try:
        with open(path, "rb") as f:
            blake2b_hash = blake2b(f.read(), digest_size=4)
            return blake2b_hash.hexdigest()
    except FileNotFoundError:
        return None


@app.template_global("is_github_oauth_enabled")
def is_github_oauth_enabled():
    """Check if GitHub OAuth is enabled"""
    return bool(
        current_app.config.get("GITHUB_OAUTH_ENABLED", False)
        and current_app.config.get("GITHUB_OAUTH_CLIENT_ID")
        and current_app.config.get("GITHUB_OAUTH_CLIENT_SECRET")
    )


# Make sure each startup clears the cache for static hashes
static_hash.delete_memoized()
