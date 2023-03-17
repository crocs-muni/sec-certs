from flask import Blueprint

vuln: Blueprint = Blueprint("vuln", __name__, url_prefix="/vuln")
vuln.cli.short_help = "Vulnerability management commands."

from .views import *
