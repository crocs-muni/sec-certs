from flask import Blueprint

pp: Blueprint = Blueprint("pp", __name__, url_prefix="/pp")
pp.cli.short_help = "Protection Profile commands."


@pp.record_once
def load_pp_data(state):
    pass


from .commands import *
from .views import *
