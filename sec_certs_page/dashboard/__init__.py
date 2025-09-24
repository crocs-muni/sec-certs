"""Initializes the Dash dashboard application and its components."""

from flask import Flask
from flask_wtf import CSRFProtect

from .. import mongo
from ..common.dash.base import Dash
from . import cc_route, fips_route
from .callback import CallbackManager
from .charts.cc.category_distribution import CCCategoryDistribution
from .charts.cc.certs_per_year import CCCertsPerYear
from .charts.cc.validity_duration import CCValidityDuration
from .charts.registry import ChartRegistry
from .data import DataService
from .filters.registry import FilterRegistry
from .layout import DashboardLayoutManager


def init_dashboard(app: Flask, csrf: CSRFProtect) -> None:
    """
    Initializes and configures the Dash dashboard application.

    :param app: The main Flask application instance.
    :type app: Flask
    :param csrf: The CSRF protection instance to exempt Dash routes.
    :type csrf: CSRFProtect
    """
    data_service = DataService(mongo=mongo)

    # Instantiate and populate the registries with predefined graphs
    cc_graph_registry = ChartRegistry()
    cc_graph_registry.register(CCCategoryDistribution("cc-category-distribution", data_service))
    cc_graph_registry.register(CCCertsPerYear("cc-certs-per-year", data_service))
    cc_graph_registry.register(CCValidityDuration("cc-validity-duration", data_service))

    # Instantiate and populate the filter registry
    cc_filter_registry = FilterRegistry()

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

    cc_route.register_pages(dash_app, cc_graph_registry, cc_filter_registry)
    fips_route.register_pages()

    dash_app.layout = layout_manager.build_layout()

    callback_manager.register_callbacks(dash_app)

    # Dash handles its own state and does not use standard CSRF tokens
    with app.app_context():

        def _exempt_all_dash_endpoints(app: Flask, csrf: CSRFProtect, url_base_pathname: str) -> None:
            """Dash is not using CSRF protection, so we need to exempt its routes."""
            for rule in app.url_map.iter_rules():
                if rule.rule.startswith(url_base_pathname):
                    view_func = app.view_functions.get(rule.endpoint)
                    if view_func is not None:
                        csrf.exempt(view_func)

        _exempt_all_dash_endpoints(app, csrf, url_base_pathname)
