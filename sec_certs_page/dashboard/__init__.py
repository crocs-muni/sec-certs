"""Initializes the Dash dashboard application and its components."""

from flask import Flask
from flask_wtf import CSRFProtect

from sec_certs_page import mongo

from ..common.dash.base import Dash
from . import cc_route, fips_route
from .callback import CallbackManager
from .data import DataService
from .graphs.cc_bar_chart import CCBarChart
from .graphs.cc_pie_chart import CCPieChart
from .graphs.registry import GraphRegistry
from .layout import DashboardLayoutManager


def init_dashboard(app: Flask, csrf: CSRFProtect) -> None:
    """Initializes and configures the Dash dashboard application."""
    data_service = DataService(mongo=mongo)

    # Instantiate and populate the registries with predefined graphs
    cc_graph_registry = GraphRegistry()
    cc_graph_registry.register(CCPieChart("cc-pie-chart", data_service))
    cc_graph_registry.register(CCBarChart("cc-bar-chart", data_service))

    layout_manager = DashboardLayoutManager(data_service=data_service)
    callback_manager = CallbackManager(cc_graph_registry=cc_graph_registry)

    url_base_pathname = "/dashboard/"
    dash_app = Dash(
        name=__name__,
        server=app,
        url_base_pathname=url_base_pathname,
        use_pages=True,
        pages_folder="",
    )

    layout_manager.register_home_page()

    cc_route.register_pages(dash_app, cc_graph_registry)
    fips_route.register_pages()

    dash_app.layout = layout_manager.build_layout()

    callback_manager.register_callbacks(dash_app)

    # Dash handles its own state and does not use standard CSRF tokens
    with app.app_context():

        def _exempt_all_dash_endpoints(app: Flask, csrf: CSRFProtect, url_base_pathname: str) -> None:
            """Exempt all Dash endpoints from CSRF protection.

            Dash is not using CSRF protection, so we need to exempt its routes.
            """
            for rule in app.url_map.iter_rules():
                if rule.rule.startswith(url_base_pathname):
                    view_func = app.view_functions.get(rule.endpoint)
                    if view_func is not None:
                        csrf.exempt(view_func)

        _exempt_all_dash_endpoints(app, csrf, url_base_pathname)
