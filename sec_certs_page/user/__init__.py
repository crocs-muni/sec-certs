from flask import Blueprint

user: Blueprint = Blueprint("user", __name__, url_prefix="/user")

from .views import *
