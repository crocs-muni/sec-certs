"""Fixed dashboard initialization with dynamic filter generation."""

import logging
from logging import Logger

from flask import Flask
from flask_wtf import CSRFProtect

from sec_certs_page.dashboard.filters.factory import DashFilterFactory
from sec_certs_page.dashboard.filters.registry import CCFilterRegistry
from sec_certs_page.dashboard.manager import DashboardManager
from sec_certs_page.dashboard.types.common import DatasetTypeName

from .. import mongo
from ..common.dash.base import Dash
from . import fips_route, pages
from .charts.cc.category_distribution import CCCategoryDistribution
from .charts.cc.certs_per_year import CCCertsPerYear
from .charts.cc.validity_duration import CCValidityDuration
from .charts.registry import ChartRegistry
from .data import DataService
from .layout import DashboardLayout

logger: Logger = logging.getLogger(__name__)


def init_dashboard(app: Flask, csrf: CSRFProtect) -> None:
    """
    Initializes and configures the Dash dashboard application with dynamic filters.

    :param app: The main Flask application instance.
    :type app: Flask
    :param csrf: The CSRF protection instance to exempt Dash routes.
    :type csrf: CSRFProtect
    """
    print("=== INITIALIZING DASHBOARD ===")

    # Initialize core classes
    data_service = DataService(mongo)

    dashboard_manager = DashboardManager()

    # Create predefined dashboard and the charts to register in it
    predefined_dashboard = dashboard_manager.create()
    predefined_cc_chart_registry = ChartRegistry(dataset_type=DatasetTypeName.CommonCriteria)

    charts = [
        CCCategoryDistribution("cc-category-distribution-v2", data_service),
        CCCertsPerYear("cc-certs-per-year-v2", data_service),
        CCValidityDuration("cc-validity-duration-v2", data_service),
    ]
    try:
        for chart in charts:
            predefined_cc_chart_registry.register(chart)
            logger.info(f"✓ Registered chart: {chart.id}")

    except Exception:
        logger.exception("✗ Error creating charts.")
        return
    predefined_fips_chart_registry = ChartRegistry(dataset_type=DatasetTypeName.FIPS140)

    # Create registries
    cc_chart_registry = ChartRegistry(dataset_type=DatasetTypeName.CommonCriteria)
    fips_chart_registry = ChartRegistry(dataset_type=DatasetTypeName.FIPS140)


    logger.info(f"✓ Registries initialized: {len(list(cc_chart_registry))} charts, filters initialized")
    # Create Dash app
    url_base_pathname = "/dashboard/"
    dash_app = Dash(
        name=__name__,
        server=app,
        url_base_pathname=url_base_pathname,
        suppress_callback_exceptions=True,
        use_pages=True,
        pages_folder="",
    )

    try:
        pages.register_pages(dash_app, cc_chart_registry)
        fips_route.register_pages()
        logger.info("✓ Routes registered successfully")

        layout_manager = DashboardLayout(data_service=data_service)
        layout_manager.register_home_page()

        try:
            import dash

            if hasattr(dash, "page_registry"):
                logger.info(f"Registered Dash pages: {list(dash.page_registry.keys())}")
                for page_name, page_info in dash.page_registry.items():
                    logger.info(f"  - {page_name}: path={page_info.get('path', 'N/A')}")
        except Exception:
            logger.exception("Could not list registered pages.")
        dash_app.layout = layout_manager.create()
        logger.info("✓ Layout configured")

    except Exception:
        logger.exception("✗ Error registering routes/layout.")
        return

    # Exempt Dash routes from CSRF
    with app.app_context():
        try:
            _exempt_all_dash_endpoints(app, csrf, url_base_pathname)
            logger.info("✓ CSRF exemptions configured")
        except Exception:
            logger.exception("✗ CSRF exemption error")

    logger.debug("=== DASHBOARD INITIALIZATION COMPLETE ===")
    logger.debug(f"Dashboard available at: http://localhost:5000{url_base_pathname}")
    logger.debug(f"CC Dashboard at: http://localhost:5000{url_base_pathname}cc")


def _exempt_all_dash_endpoints(app: Flask, csrf: CSRFProtect, url_base_pathname: str) -> None:
    """Dash is not using CSRF protection, so we need to exempt its routes."""
    for rule in app.url_map.iter_rules():
        if rule.rule.startswith(url_base_pathname):
            view_func = app.view_functions.get(rule.endpoint)
            if view_func is not None:
                csrf.exempt(view_func)
