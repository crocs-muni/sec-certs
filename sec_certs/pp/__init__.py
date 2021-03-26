import json

from flask import Blueprint, current_app

pp = Blueprint("pp", __name__, url_prefix="/pp")

pp_data = {}


@pp.before_app_first_request
def load_pp_data():
    global pp_data
    with current_app.open_instance_resource("pp.json") as f:
        loaded_pp_data = json.load(f)
    pass


from .views import *
