import logging
from logging import Logger

import dash
import dash_bootstrap_components as dbc
from dash import html
from flask import Flask, abort, redirect, request, url_for
from flask_login import current_user
from flask_wtf import CSRFProtect

from ..common.permissions import dashboard_permission
from .base import Dash
from .callbacks import register_all_callbacks
from .data import DataService
from .manager import DashboardManager

logger: Logger = logging.getLogger(__name__)


def layout(**kwargs) -> dbc.Container:
    """
    App shell layout with safe Server-Side Injection.

    **The Problem (Blank Page Issue):**
    Standard Dash Pages applications function as SPAs: the server returns an empty shell, and
    the client-side router (`dcc.Location`) asynchronously triggers a callback to render the
    content. When embedding Dash deeply within a Flask/Jinja2 environment, this initial
    client-side routing event often fails to trigger.

    **The Fix (Server-Side Injection):**
    The system implements a manual Server-Side Rendering (SSR) step - inspecting the path, resolving the
    Dash page manually, and inject the resulting component tree directly into dash.page_container.
    """

    return dbc.Container(
        fluid=True,
        className="col-12 col-sm-10 mx-auto p-3 py-md-5",
        children=[
            # Header
            dbc.Row(
                className="mb-4 pb-3 border-bottom",
                children=[
                    dbc.Col(
                        children=[
                            html.H1(
                                [
                                    html.I(className="fas fa-chart-line me-3"),
                                    "Data Analysis",
                                ],
                                className="mb-2",
                            ),
                        ],
                    ),
                ],
            ),
            dbc.Alert(
                [
                    html.I(className="fas fa-exclamation-triangle me-2"),
                    "This dashboard was not yet optimized for use on mobile devices.",
                ],
                color="warning",
                className="d-sm-none",
                dismissable=True,
            ),
            # Page content
            dash.page_container,
        ],
    )


def init_dashboard(dash_app: Dash, flask_app: Flask, csrf: CSRFProtect):
    """
    Initializes and configures the Dash dashboard application with dynamic filters.

    :param dash_app: The Dash application instance.
    :type dash_app: Dash
    """
    from .. import mongo

    logger.debug("=== INITIALIZING DASHBOARD ===")
    dash_app.layout = layout

    data_service = DataService(mongo)
    dashboard_manager = DashboardManager(data_service)

    dashboard_manager.register_predefined_charts()

    register_all_callbacks(
        dash_app=dash_app,
        data_service=data_service,
        dashboard_manager=dashboard_manager,
        filter_factories=dashboard_manager.filter_factories,
        chart_registries=dashboard_manager.chart_registries,
    )

    url_base_pathname = dash_app.config.url_base_pathname
    _register_dashboard_protection(dash_app, url_base_pathname)

    _exempt_all_dash_endpoints(flask_app, csrf, url_base_pathname)


def _register_dashboard_protection(dash_app: Dash, url_base_pathname: str) -> None:
    """
    Protect dashboard routes with role-based authentication.

    This registers a before_request handler scoped to dashboard URLs only.
    Uses the Dash app's url_base_pathname to determine which routes to protect.
    """
    server = dash_app.server

    @server.before_request
    def check_dashboard_access():
        if not request.path.startswith(url_base_pathname):
            return None

        if not current_user.is_authenticated:
            return redirect(url_for("user.login", next=request.url))

        if not dashboard_permission.can():
            abort(403)


def _exempt_all_dash_endpoints(app: Flask, csrf: CSRFProtect, url_base_pathname: str) -> None:
    """Dash is not using CSRF protection, so we need to exempt its routes."""
    for rule in app.url_map.iter_rules():
        if rule.rule.startswith(url_base_pathname):
            view_func = app.view_functions.get(rule.endpoint)
            if view_func is not None:
                csrf.exempt(view_func)
