import logging
from logging import Logger

import dash
import flask
from dash import dcc, html
from dash._pages import PAGE_REGISTRY, _path_to_page

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


def init_dashboard(dash_app: Dash):
    """
    Initializes and configures the Dash dashboard application with dynamic filters.

    :param dash_app: The Dash application instance.
    :type dash_app: Dash
    """
    global _dashboard_manager, _data_service

    logger.debug("=== INITIALIZING DASHBOARD ===")

    # Pages are auto-discovered from pages_folder setting in Dash constructor
    # No need to manually register them

    # Set layout - this must happen after Dash has auto-discovered pages
    # so dash.page_container can set up the routing callback
    dash_app.layout = layout

    _data_service = DataService(mongo)
    _dashboard_manager = DashboardManager(_data_service)

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


def _get_initial_page_content():
    """
    Get the initial page content based on the current request path.

    This is needed because Dash's page_container uses prevent_initial_call=True
    and relies on client-side JS to trigger the first page load.
    We pre-render the initial page content server-side.
    """
    try:
        # Get the current request path, stripping the /dashboard/ prefix
        path = flask.request.path
        path = path.replace("/dashboard", "").rstrip("/") or "/"

        # Find the matching page
        page, path_variables = _path_to_page(path.strip("/"))

        if page:
            layout_func = page.get("layout")
            if callable(layout_func):
                return layout_func(**(path_variables or {}))
            return layout_func
    except Exception as e:
        logger.warning(f"Failed to get initial page content: {e}")

    return None


def layout(**kwargs) -> html.Div:
    """
    App shell layout - contains only header and page container.

    Individual pages are rendered within dash.page_container.
    We pre-populate _pages_content with the initial page to avoid blank page on load.
    """
    # Get initial page content and inject it into page_container
    initial_content = _get_initial_page_content()

    # Find and update _pages_content in page_container
    if initial_content is not None:
        for child in dash.page_container.children:
            if hasattr(child, "id") and child.id == "_pages_content":
                child.children = initial_content
                break

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
