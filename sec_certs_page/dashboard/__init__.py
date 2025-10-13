"""Fixed dashboard initialization with dynamic filter generation."""

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
from .filters.dynamic_factory import FilterFactory
from .filters.registry import FilterRegistry
from .layout import DashboardLayoutManager


def init_dashboard(app: Flask, csrf: CSRFProtect) -> None:
    """
    Initializes and configures the Dash dashboard application with dynamic filters.

    :param app: The main Flask application instance.
    :type app: Flask
    :param csrf: The CSRF protection instance to exempt Dash routes.
    :type csrf: CSRFProtect
    """
    print("=== INITIALIZING DASHBOARD ===")

    # Initialize core services
    data_service = DataService(mongo)

    # Create registries
    cc_chart_registry = ChartRegistry()
    cc_filter_registry = FilterRegistry()

    # Create and register charts with UNIQUE IDs
    try:
        charts = [
            CCCategoryDistribution("cc-category-distribution-v2", data_service),
            CCCertsPerYear("cc-certs-per-year-v2", data_service),
            CCValidityDuration("cc-validity-duration-v2", data_service),
        ]

        for chart in charts:
            cc_chart_registry.register(chart)
            print(f"✓ Registered chart: {chart.id}")

    except Exception as e:
        print(f"✗ Error creating charts: {e}")
        return

    # Create filter factory but don't create filters yet - they'll be created when pages are visited
    filter_factory = FilterFactory(data_service)
    print("✓ Filter factory created (filters will be created on-demand when pages are visited)")

    print(f"✓ Registries initialized: {len(list(cc_chart_registry))} charts, 0 filters (will be created on-demand)")

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

    # CRITICAL FIX: Register routes BEFORE setting layout
    try:
        cc_route.register_pages(dash_app, cc_chart_registry, cc_filter_registry, filter_factory)
        fips_route.register_pages()
        print("✓ Routes registered successfully")

        # Register home page
        layout_manager = DashboardLayoutManager(data_service=data_service)
        layout_manager.register_home_page()

        # Debug: List all registered pages
        try:
            import dash

            if hasattr(dash, "page_registry"):
                print(f"Registered Dash pages: {list(dash.page_registry.keys())}")
                for page_name, page_info in dash.page_registry.items():
                    print(f"  - {page_name}: path={page_info.get('path', 'N/A')}")
        except Exception as e:
            print(f"Could not list registered pages: {e}")

        # Set main layout
        dash_app.layout = layout_manager.build_layout()
        print("✓ Layout configured")

    except Exception as e:
        print(f"✗ Error registering routes/layout: {e}")
        return

    # OPTIONAL: Use callback manager if you want centralized callback registration
    # Note: Charts already register their own callbacks in cc_route.register_pages()
    try:
        # callback_manager = CallbackManager(cc_chart_registry=cc_chart_registry)
        # callback_manager.register_callbacks(dash_app)  # Disabled to prevent double registration
        print("✓ Callback manager not instantiated to prevent double registration")
    except Exception as e:
        print(f"WARNING: Callback manager error: {e}")

    # Exempt Dash routes from CSRF
    with app.app_context():
        try:
            _exempt_all_dash_endpoints(app, csrf, url_base_pathname)
            print("✓ CSRF exemptions configured")
        except Exception as e:
            print(f"WARNING: CSRF exemption error: {e}")

    print("=== DASHBOARD INITIALIZATION COMPLETE ===")
    print(f"Dashboard available at: http://localhost:5000{url_base_pathname}")
    print(f"CC Dashboard at: http://localhost:5000{url_base_pathname}cc")


def _exempt_all_dash_endpoints(app: Flask, csrf: CSRFProtect, url_base_pathname: str) -> None:
    """Dash is not using CSRF protection, so we need to exempt its routes."""
    for rule in app.url_map.iter_rules():
        if rule.rule.startswith(url_base_pathname):
            view_func = app.view_functions.get(rule.endpoint)
            if view_func is not None:
                csrf.exempt(view_func)
