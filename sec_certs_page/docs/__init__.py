from flask import Blueprint

docs: Blueprint = Blueprint("docs", __name__, url_prefix="/docs")

from .views import *
