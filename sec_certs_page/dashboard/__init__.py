# dashboard
from flask import Flask
from flask_wtf import CSRFProtect

from ..common.dash.base import Dash
from .callback import CallbackManager
from .layout import DashboardLayoutManager


def init_dashboard(app: Flask, csrf: CSRFProtect) -> None:
    """
    Initializes and configures the Dash dashboard application, attaching it to the main Flask app.
    This function encapsulates all setup logic for the dashboard.
    """
    url_base_pathname = "/dashboard/"

    # Instantiate the Dash app, linking it to the existing Flask server
    dash_app = Dash(
        name=__name__,
        server=app,
        url_base_pathname=url_base_pathname,
        use_pages=True,
        pages_folder="",
    )

    # Import and register pages AFTER app creation
    from . import cc_route

    cc_route.register_pages()

    # Exempt the main Dash views from CSRF protection, as it handles its own state via callbacks
    # Dash registers multiple Flask routes under the configured base path. Exempt them all.
    for rule in app.url_map.iter_rules():
        if rule.rule.startswith(url_base_pathname):
            view_func = app.view_functions.get(rule.endpoint)
            if view_func is not None:
                csrf.exempt(view_func)

    layout_manager = DashboardLayoutManager()
    callback_manager = CallbackManager()

    dash_app.layout = layout_manager.build_layout()

    # Register all application callbacks
    callback_manager.register_callbacks(dash_app)
