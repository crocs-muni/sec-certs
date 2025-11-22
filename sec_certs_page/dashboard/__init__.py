import logging
from logging import Logger

from flask import Flask
from flask_wtf import CSRFProtect

from .. import mongo
from ..common.dash.base import Dash
from .callbacks import register_all_callbacks
from .data import DataService
from .layout import DashboardLayout
from .manager import DashboardManager
from .pages import register_pages

logger: Logger = logging.getLogger(__name__)


def init_dashboard(app: Flask, csrf: CSRFProtect) -> Dash:
    """
    Initializes and configures the Dash dashboard application with dynamic filters.

    :param app: The main Flask application instance.
    :type app: Flask
    :param csrf: The CSRF protection instance to exempt Dash routes.
    :type csrf: CSRFProtect
    """
    print("=== INITIALIZING DASHBOARD ===")

    # Create core services
    data_service = DataService(mongo)
    dashboard_manager = DashboardManager(data_service)

    # Register predefined charts
    dashboard_manager.register_predefined_charts()

    url_base_pathname = "/dashboard"
    dash_app = Dash(
        __name__,
        server=app,
        use_pages=True,
        suppress_callback_exceptions=True,
        pages_folder="",
    )

    # Create and set layout
    layout_builder = DashboardLayout(data_service)
    dash_app.layout = layout_builder.create()
    layout_builder.register_home_page()

    # Register pages (just layouts, no callbacks)
    register_pages(
        filter_factories=dashboard_manager.filter_factories,
        chart_registries=dashboard_manager.chart_registries,
    )

    # Register all callbacks
    register_all_callbacks(
        app=dash_app,
        data_service=data_service,
        filter_factories=dashboard_manager.filter_factories,
        chart_registries=dashboard_manager.chart_registries,
    )

    with app.app_context():
        try:
            _exempt_all_dash_endpoints(app, csrf, url_base_pathname)
            logger.info("✓ CSRF exemptions configured")
        except Exception:
            logger.exception("✗ CSRF exemption error")

    logger.debug("=== DASHBOARD INITIALIZATION COMPLETE ===")
    logger.debug(f"Dashboard available at: http://localhost:5000{url_base_pathname}")
    logger.debug(f"CC Dashboard at: http://localhost:5000{url_base_pathname}/cc")

    return dash_app


def _exempt_all_dash_endpoints(app: Flask, csrf: CSRFProtect, url_base_pathname: str) -> None:
    """Dash is not using CSRF protection, so we need to exempt its routes."""
    for rule in app.url_map.iter_rules():
        if rule.rule.startswith(url_base_pathname):
            view_func = app.view_functions.get(rule.endpoint)
            if view_func is not None:
                csrf.exempt(view_func)
