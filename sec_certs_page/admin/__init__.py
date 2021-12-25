from flask import Blueprint

admin: Blueprint = Blueprint("admin", __name__, url_prefix="/admin")

from .commands import *
from .views import *
