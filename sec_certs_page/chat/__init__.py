from flask import Blueprint

chat: Blueprint = Blueprint("chat", __name__, url_prefix="/chat")

from .views import *
