from flask import Blueprint

pp: Blueprint = Blueprint("pp", __name__, url_prefix="/pp")
pp.cli.short_help = "Protection Profile commands."

from .commands import *
from .views import *
