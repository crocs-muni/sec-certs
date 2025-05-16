from flask import Blueprint

about: Blueprint = Blueprint("about", __name__, url_prefix="/about")

from .views import *
