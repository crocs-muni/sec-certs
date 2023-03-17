from flask import Blueprint

notifications: Blueprint = Blueprint("notify", __name__, url_prefix="/notify")

from .tasks import *
from .views import *
