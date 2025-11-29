"""
Dashboard initialization module with Server-Side Rendering (SSR) fix for Dash Pages.

SSR Fix for Dash Pages Blank Page Issue
========================================

The Problem
-----------
Dash Pages is designed as a Single Page Application (SPA). When a user visits
a URL like ``/dashboard/``, Dash returns an HTML shell with an empty ``_pages_content``
div, then relies on client-side JavaScript to:

1. Read the current URL via ``dcc.Location``
2. Trigger a callback to fetch and render the appropriate page content

However, when Dash is embedded within a Flask application using ``url_base_pathname``
(e.g., ``/dashboard/``), this client-side routing often fails on initial page load.
The ``dcc.Location`` component doesn't fire the routing callback, leaving users
with a blank page showing only the app shell (header, etc.) but no page content.

This is particularly problematic because:

- Direct navigation to ``/dashboard/`` shows blank content
- Refreshing any dashboard page shows blank content
- Only client-side navigation (clicking links) works correctly

The Solution
------------
System implements Server-Side Rendering (SSR) for the initial page load:

1. When ``layout()`` is called, system inspects the current Flask request path
2. System resolve which Dash page matches that path using Werkzeug's URL routing
3. System calls that page's layout function server-side
4. System injects the result directly into ``dash.page_container.children[1]``
   (the ``_pages_content`` div) before sending HTML to the client

This ensures the initial HTML payload contains the correct page content,
eliminating the blank page issue. Client-side routing still works normally
for subsequent navigation.

Important Notes
---------------
- System skips SSR for internal Dash routes (``/_dash-layout``, ``/_dash-dependencies``)
  as these are AJAX requests for client-side hydration
- System mutates ``dash.page_container`` singleton, which is safe because:

  - Flask dev server is single-threaded
  - Production workers (gunicorn/uwsgi) each have their own process

- If SSR fails for any reason, system gracefully fall back to client-side routing

Thread Safety Caveat
--------------------
If using threaded mode (Flask's ``threaded=True`` or gunicorn's ``--threads``),
there's a theoretical race condition where two concurrent requests could
interfere. In practice, this would only cause a brief flash of wrong content
that gets corrected by client-side routing. For production, prefer multiple
workers over multiple threads.
"""

import logging
from logging import Logger

import dash
import dash_bootstrap_components as dbc
import flask
from dash import dcc, html
from dash.development.base_component import Component
from werkzeug.exceptions import HTTPException, NotFound
from werkzeug.routing import Map, RequestRedirect, Rule

from .. import mongo
from ..common.dash.base import Dash
from .callbacks import register_all_callbacks
from .data import DataService
from .manager import DashboardManager

logger: Logger = logging.getLogger(__name__)


class PageRouter:
    """
    Handles Server-Side Rendering (SSR) routing for Dash Pages.
    Fixes the 'blank page' issue by resolving the URL and pre-rendering the
    correct page layout on the server before the client-side router takes over.
    """

    def __init__(self):
        self._url_map = None

    @property
    def url_map(self) -> Map:
        """Lazy-load the route map to ensure dash.page_registry is populated."""
        if self._url_map is None:
            rules = []
            for page in dash.page_registry.values():
                # Use the template (e.g., /report/<id>) if available, otherwise the static path
                path = page.get("path_template") or page.get("path")
                if path:
                    # Map the path to the page module name
                    rules.append(Rule(path, endpoint=page["module"]))
            self._url_map = Map(rules)
        return self._url_map

    def get_initial_content(self) -> Component | None:
        """
        Resolve the current request path to a Dash page layout server-side.
        """
        try:
            raw_path = flask.request.path

            # Skip SSR for internal Dash routes (AJAX requests for layout/dependencies)
            if "/_dash-" in raw_path or "/_reload-hash" in raw_path:
                return None

            # Strip the url_base_pathname prefix
            clean_path = dash.strip_relative_path(raw_path)

            # Normalize: empty string becomes "/", otherwise prepend "/"
            if clean_path is not None and not clean_path.startswith("/"):
                clean_path = "/" + clean_path

            # Match path against registered pages
            urls = self.url_map.bind_to_environ(flask.request.environ)
            try:
                module_name, path_variables = urls.match(clean_path)
                page = dash.page_registry.get(module_name)
                if page:
                    layout_func = page["layout"]
                    if callable(layout_func):
                        return layout_func(**(path_variables or {}))
                    return layout_func
            except (NotFound, RequestRedirect, HTTPException):
                pass  # No matching page, client-side router will handle

        except Exception as e:
            logger.warning(f"SSR failed for {flask.request.path}: {e}")

        return None


# Global router instance
page_router = PageRouter()


def layout(**kwargs) -> dbc.Container:
    """
    App shell layout with safe Server-Side Injection.

    **The Problem (Blank Page Issue):**
    Standard Dash Pages applications function as SPAs: the server returns an empty shell, and
    the client-side router (`dcc.Location`) asynchronously triggers a callback to render the
    content. When embedding Dash deeply within a Flask/Jinja2 environment, this initial
    client-side routing event often fails to trigger.

    **The Fix (Server-Side Injection):**
    We implement a manual Server-Side Rendering (SSR) step. We inspect the path, resolve the
    Dash page manually, and inject the resulting component tree directly into dash.page_container.
    """

    initial_content = page_router.get_initial_content()

    # Inject SSR content into dash.page_container
    # The page_container structure is: [Location, content_div, Store, dummy_div]
    # We inject into children[1] which is the _pages_content div
    if initial_content is not None and dash.page_container.children is not None:
        dash.page_container.children[1].children = initial_content

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
                                    "sec-certs.org Data Dashboards",
                                ],
                                className="mb-2",
                            ),
                            dbc.Nav(
                                children=[
                                    dbc.NavItem(
                                        dcc.Link(
                                            [html.I(className="fas fa-home me-1"), "Dashboard Home"],
                                            href="/dashboard/",
                                            className="nav-link",
                                        ),
                                    ),
                                    dbc.NavItem(
                                        dcc.Link(
                                            [html.I(className="fas fa-shield-alt me-1"), "Common Criteria"],
                                            href="/dashboard/cc",
                                            className="nav-link",
                                        ),
                                    ),
                                    dbc.NavItem(
                                        dcc.Link(
                                            [html.I(className="fas fa-lock me-1"), "FIPS 140"],
                                            href="/dashboard/fips",
                                            className="nav-link",
                                        ),
                                    ),
                                ],
                                pills=True,
                            ),
                        ],
                    ),
                ],
            ),
            # Alert for mobile users
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


def init_dashboard(dash_app: Dash):
    """
    Initializes and configures the Dash dashboard application with dynamic filters.

    :param dash_app: The Dash application instance.
    :type dash_app: Dash
    """
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

    logger.debug("=== DASHBOARD INITIALIZATION COMPLETE ===")
    logger.debug(f"Registered pages: {list(dash.page_registry.keys())}")
