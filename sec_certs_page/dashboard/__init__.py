import logging
from logging import Logger

import dash
from dash import dcc, html

from .. import mongo
from ..common.dash.base import Dash
from .callbacks import register_all_callbacks
from .data import DataService
from .manager import DashboardManager

logger: Logger = logging.getLogger(__name__)

# Module-level references for access by page modules
_dashboard_manager: DashboardManager | None = None
_data_service: DataService | None = None


def get_dashboard_manager() -> DashboardManager:
    """Get the dashboard manager instance."""
    if _dashboard_manager is None:
        raise RuntimeError("Dashboard not initialized. Call init_dashboard first.")
    return _dashboard_manager


def get_data_service() -> DataService:
    """Get the data service instance."""
    if _data_service is None:
        raise RuntimeError("Dashboard not initialized. Call init_dashboard first.")
    return _data_service


def _register_pages() -> None:
    """Import and register all dashboard pages with Dash."""
    # These imports trigger dash.register_page() calls
    from . import home  # noqa: F401
    from .pages import cc, fips  # noqa: F401


def init_dashboard(dash_app: Dash):
    """
    Initializes and configures the Dash dashboard application with dynamic filters.

    :param dash_app: The Dash application instance.
    :type dash_app: Dash
    """
    global _dashboard_manager, _data_service

    logger.debug("=== INITIALIZING DASHBOARD ===")

    # Register pages first (must be done after app creation but before layout)
    _register_pages()

    _data_service = DataService(mongo)
    _dashboard_manager = DashboardManager(_data_service)

    dash_app.layout = layout

    _dashboard_manager.register_predefined_charts()

    register_all_callbacks(
        dash_app=dash_app,
        data_service=_data_service,
        dashboard_manager=_dashboard_manager,
        filter_factories=_dashboard_manager.filter_factories,
        chart_registries=_dashboard_manager.chart_registries,
    )

    logger.debug("=== DASHBOARD INITIALIZATION COMPLETE ===")
    logger.debug(f"Registered pages: {list(dash.page_registry.keys())}")


def layout(**kwargs) -> html.Div:
    """
    App shell layout - contains only header and page container.

    Individual pages are rendered within dash.page_container.
    """
    return html.Div(
        children=[
            html.Header(
                children=[
                    html.H1(
                        "Security Certification Data Dashboards",
                        style={"margin": "0 0 10px 0"},
                    ),
                    dcc.Link("Home", href="/", style={"marginRight": "15px"}),
                ],
                style={"borderBottom": "1px solid #ddd", "paddingBottom": "10px", "marginBottom": "20px"},
            ),
            dash.page_container,
        ],
    )
