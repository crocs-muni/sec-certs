from flask import Blueprint

sesip: Blueprint = Blueprint("sesip", __name__, url_prefix="/sesip")
sesip.cli.short_help = "SESIP commands."

from .views import *
