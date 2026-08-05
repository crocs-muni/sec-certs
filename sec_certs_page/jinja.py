import re
import time
from datetime import date, datetime
from pathlib import Path

import sentry_sdk
from flag import flag
from flask import current_app, request
from flask_principal import Permission, RoleNeed
from markupsafe import Markup
from nacl.hashlib import blake2b
from sec_certs.utils.extract import flatten_matches as dict_flatten
from sentry_sdk.utils import get_default_release

from . import app, cache, runtime_config
from .common.constants import JAVACARD_PACKAGES_LOOKUP, PKCS_RFC
from .common.keyword_groups import KEYWORD_GROUPS, build_keyword_tree

app.add_template_global(KEYWORD_GROUPS, "KEYWORD_GROUPS")
app.add_template_global(build_keyword_tree, "keyword_tree")


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
    if isinstance(dt_obj, (datetime, date)):
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
            with (Path(bp.static_folder) / filename).open(encoding="utf-8") as f:
                return Markup(f.read())
        except FileNotFoundError:
            return None
    elif current_app.static_folder is not None:
        try:
            with (Path(current_app.static_folder) / filename).open(encoding="utf-8") as f:
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
        path = Path(bp.static_folder) / filename
    elif current_app.static_folder is not None:
        path = Path(current_app.static_folder) / filename
    else:
        return None

    try:
        with path.open("rb") as f:
            blake2b_hash = blake2b(f.read(), digest_size=4)
            return blake2b_hash.hexdigest()
    except FileNotFoundError:
        return None


@app.template_global("standard_url")
def standard_url(standard):
    # return URL for a matched standard identifier or none if unknown
    s = standard.strip()

    m = re.match(r"RFC[ -]?(\d+)", s, re.IGNORECASE)
    if m:
        return f"https://www.rfc-editor.org/rfc/rfc{m.group(1)}"

    m = re.match(r"FIPS\s*(?:PUB\s*)?(\d+)(?:-(\d+))?", s, re.IGNORECASE)
    if m:
        base, sub = m.group(1), m.group(2)
        path = f"{base}-{sub}" if sub else base
        return f"https://csrc.nist.gov/pubs/fips/{path}/final"

    if re.match(r"(?:NIST\s+)?SP[\s-]*\d", s, re.IGNORECASE):
        return "https://csrc.nist.gov/publications/sp"

    if re.match(r"X[.．]?509", s, re.IGNORECASE):
        return "https://www.itu.int/rec/T-REC-X.509"

    if re.match(r"ICAO", s, re.IGNORECASE):
        return "https://www.icao.int/publications/doc-series"

    if re.match(r"(?:BSI[- ]?)?AIS", s, re.IGNORECASE):
        return (
            "https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/"
            "Standards-und-Zertifizierung/Zertifizierung-und-Anerkennung/"
            "Zertifizierung-von-Produkten/Zertifizierung-nach-CC/"
            "Anwendungshinweise-und-Interpretationen/"
            "anwendungshinweise-und-interpretationen_node.html"
        )

    m = re.match(r"PKCS\s*#?\s*(\d+)", s, re.IGNORECASE)
    if m:
        rfc = PKCS_RFC.get(int(m.group(1)))
        if rfc:
            return f"https://www.rfc-editor.org/rfc/rfc{rfc}"
        return "https://en.wikipedia.org/wiki/PKCS"

    if re.match(r"PKCS", s, re.IGNORECASE):
        return "https://en.wikipedia.org/wiki/PKCS"

    if re.match(r"SCP", s, re.IGNORECASE):
        return "https://globalplatform.org/specs-library/"

    m = re.match(r"ISO(?:/IEC)?\s*(\d+)", s, re.IGNORECASE)
    if m:
        return f"https://www.iso.org/search.html?q={m.group(1)}"

    return None


@app.template_global("curve_url")
def curve_url(curve):
    # return URL of a named elliptic curve in the Standard Curve Database or none
    c = re.sub(r"^(?:NIST|ANSSI|Curve)\s+", "", curve.strip(), flags=re.IGNORECASE)
    base = "https://neuromancer.sk/std"

    if re.fullmatch(r"P-\d+", c, re.IGNORECASE):
        return f"{base}/nist/{c.upper()}"

    m = re.fullmatch(r"([BK])-(\d+)", c, re.IGNORECASE)
    if m:
        return f"{base}/nist/{m.group(1).upper()}-{m.group(2)}"

    if re.fullmatch(r"sec[pt]\d+[rk]\d", c, re.IGNORECASE):
        return f"{base}/secg/{c}"

    if re.fullmatch(r"brainpoolP\d+[rt]\d", c, re.IGNORECASE):
        return f"{base}/brainpool/{c}"

    if re.fullmatch(r"prime\d+v\d|c2[a-z]+\d+[vw]\d", c, re.IGNORECASE):
        return f"{base}/x962/{c}"

    if re.fullmatch(r"FRP\d+v\d", c, re.IGNORECASE):
        return f"{base}/anssi/{c}"

    if re.fullmatch(r"Curve25519|Curve448|Ed25519|Ed448", c, re.IGNORECASE):
        return f"{base}/other/{c}"

    return None


@app.template_global("package_url")
def package_url(package):
    # return URL of a JavaCard API package in the official Oracle docs or none
    name = package.strip().replace("．", ".").lower()
    canonical = JAVACARD_PACKAGES_LOOKUP.get(name)
    if not canonical:
        return None
    path = canonical.replace(".", "/")
    return f"https://docs.oracle.com/en/java/javacard/3.2/jcapi/api_classic/{path}/package-summary.html"


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
