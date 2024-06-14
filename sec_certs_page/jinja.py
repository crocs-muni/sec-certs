import re
import time
from datetime import date, datetime

import sentry_sdk
from flag import flag
from flask import request
from flask_principal import Permission, RoleNeed
from sec_certs.utils.extract import flatten_matches as dict_flatten
from sentry_sdk.utils import get_default_release

from . import app


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


release = get_default_release()


@app.template_global()
def get_release():
    return release
