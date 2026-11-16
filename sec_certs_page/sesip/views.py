"""SESIP views."""

from flask import render_template

from ..common.views import register_breadcrumb
from . import sesip


@sesip.route("/")
@register_breadcrumb(sesip, ".", "SESIP")
def index():
    """SESIP index."""
    return render_template("sesip/index.html.jinja2")
