from flask import Blueprint

pp: Blueprint = Blueprint("pp", __name__, url_prefix="/pp")
pp.cli.short_help = "Protection Profile commands."


@pp.before_app_first_request
def load_pp_data():
    pass


from .commands import *
from .views import *
