"""Common utilities for dashboard collection pages."""

import dash_bootstrap_components as dbc
from dash import dcc, html

from ... import DASHBOARD_URL_BASE_PATHNAME
from ..types.common import CollectionName


def create_collection_page_layout(collection: CollectionName, title: str) -> html.Div:
    """
    Create the complete layout for a collection dashboard page.

    :param collection: The collection enum value
    :param title: The page title to display
    :return: Complete page layout
    """
    prefix = collection.value

    return html.Div(
        children=[
            # State stores
            *create_page_stores(prefix),
            # Page header
            dbc.Row(
                className="mb-4",
                children=[
                    dbc.Col(
                        children=[
                            html.H1(title, className="mb-2"),
                            dcc.Link(
                                [html.I(className="fas fa-arrow-left me-2"), "Back to Dashboard Home"],
                                href=f"{DASHBOARD_URL_BASE_PATHNAME.rstrip('/')}",
                                className="text-muted text-decoration-none",
                            ),
                        ],
                    ),
                ],
            ),
            # Dashboard management section
            dbc.Card(
                className="mb-4",
                children=[
                    dbc.CardBody(
                        children=[
                            create_dashboard_management_buttons(prefix),
                        ],
                    ),
                ],
            ),
            # Empty state
            create_empty_state(prefix),
            # Dashboard content
            create_dashboard_content(prefix),
        ],
    )


def create_page_stores(collection_name: str) -> list:
    """
    Create the common dcc.Store components used by collection pages.

    :param collection_name: The collection name (e.g., "cc", "fips")
    :return: List of dcc.Store components
    """
    return [
        dcc.Store(id=f"{collection_name}-collection-name", data=collection_name),
        dcc.Store(id=f"{collection_name}-current-dashboard-id", data=None),
        dcc.Store(id=f"{collection_name}-active-charts-store", data=[]),
        dcc.Store(id=f"{collection_name}-filter-store", data={}),
        dcc.Store(id=f"{collection_name}-render-trigger", data=0),
        dcc.Store(id=f"{collection_name}-dashboard-loaded", data=False),
    ]


def create_dashboard_management_buttons(collection_name: str) -> dbc.Row:
    """
    Create the dashboard management buttons (Create New, Load Predefined).

    :param collection_name: The collection_name for component IDs
    :return: Row containing the action buttons
    """
    return dbc.Row(
        className="g-3 align-items-end",
        children=[
            # Dashboard selector
            dbc.Col(
                width=12,
                lg=4,
                children=[
                    dbc.Label(
                        "Select Dashboard", html_for=f"{collection_name}-dashboard-selector", className="fw-bold"
                    ),
                    dcc.Dropdown(
                        id=f"{collection_name}-dashboard-selector",
                        options=[],
                        placeholder="Select a saved dashboard...",
                        clearable=True,
                        className="dash-bootstrap",
                    ),
                ],
            ),
            # Create new button
            dbc.Col(
                width="auto",
                children=[
                    dbc.Button(
                        [html.I(className="fas fa-plus me-2"), "Create New Dashboard"],
                        id=f"{collection_name}-create-dashboard-btn",
                        n_clicks=0,
                        color="success",
                        className="w-100",
                    ),
                ],
            ),
            # Load predefined button
            dbc.Col(
                width="auto",
                children=[
                    dbc.Button(
                        [html.I(className="fas fa-chart-bar me-2"), "Load Predefined Charts"],
                        id=f"{collection_name}-load-predefined-btn",
                        n_clicks=0,
                        color="primary",
                        className="w-100",
                    ),
                ],
            ),
        ],
    )


def create_empty_state(collection_name: str) -> html.Div:
    """
    Create the empty state display when no dashboard is selected.

    :param collection_name: The collection_name for component IDs
    :return: Div with empty state content
    """
    return html.Div(
        id=f"{collection_name}-empty-state",
        style={"display": "block"},
        children=[
            dbc.Card(
                className="text-center border-2 border-dashed",
                children=[
                    dbc.CardBody(
                        className="py-5",
                        children=[
                            html.I(className="fas fa-chart-line fa-3x text-muted mb-3"),
                            html.H3("No Dashboard Selected", className="text-muted"),
                            html.P(
                                "Create a new dashboard or select an existing one from the dropdown above.",
                                className="text-muted lead",
                            ),
                        ],
                    ),
                ],
            ),
        ],
    )


def create_chart_controls(collection_name: str) -> dbc.Card:
    """
    Create the chart selection and addition controls.

    :param collection_name: The collection_name for component IDs
    :return: Card containing chart controls
    """
    return dbc.Card(
        className="mb-4",
        children=[
            dbc.CardHeader(
                html.H4("Add Charts", className="mb-0"),
            ),
            dbc.CardBody(
                children=[
                    dbc.Row(
                        className="g-3 align-items-end",
                        children=[
                            dbc.Col(
                                width=12,
                                md=6,
                                lg=4,
                                children=[
                                    dbc.Label(
                                        "Select Chart Type",
                                        html_for=f"{collection_name}-chart-selector",
                                        className="fw-bold",
                                    ),
                                    dcc.Dropdown(
                                        id=f"{collection_name}-chart-selector",
                                        options=[],
                                        placeholder="Select a chart to add...",
                                        className="dash-bootstrap",
                                    ),
                                ],
                            ),
                            dbc.Col(
                                width="auto",
                                children=[
                                    dbc.Button(
                                        [html.I(className="fas fa-plus me-2"), "Add Chart"],
                                        id=f"{collection_name}-add-chart-btn",
                                        n_clicks=0,
                                        color="success",
                                    ),
                                ],
                            ),
                        ],
                    ),
                ],
            ),
        ],
    )


def create_dashboard_action_buttons(collection_name: str) -> dbc.Row:
    """
    Create the dashboard action buttons (Update All, Save).

    :param collection_name: The collection_name for component IDs
    :return: Row containing action buttons
    """
    return dbc.Row(
        className="mb-4 g-2",
        children=[
            dbc.Col(
                width="auto",
                children=[
                    dbc.Button(
                        [html.I(className="fas fa-sync-alt me-2"), "Update All Charts"],
                        id=f"{collection_name}-update-all-btn",
                        n_clicks=0,
                        disabled=True,
                        color="success",
                        outline=True,
                    ),
                ],
            ),
            dbc.Col(
                width="auto",
                children=[
                    dbc.Button(
                        [html.I(className="fas fa-save me-2"), "Save Dashboard"],
                        id=f"{collection_name}-save-dashboard-btn",
                        n_clicks=0,
                        disabled=True,
                        color="primary",
                    ),
                ],
            ),
        ],
    )


def create_dashboard_content(collection_name: str) -> html.Div:
    """
    Create the dashboard content area shown when a dashboard is active.

    :param collection_name: The collection_name for component IDs
    :return: Div containing dashboard content
    """
    return html.Div(
        id=f"{collection_name}-dashboard-content",
        style={"display": "none"},
        children=[
            # Dashboard name input
            dbc.Card(
                className="mb-4",
                children=[
                    dbc.CardBody(
                        children=[
                            dbc.Row(
                                className="align-items-center",
                                children=[
                                    dbc.Col(
                                        width=12,
                                        md=6,
                                        children=[
                                            dbc.Label(
                                                "Dashboard Name",
                                                html_for=f"{collection_name}-dashboard-name-input",
                                                className="fw-bold",
                                            ),
                                            dbc.Input(
                                                id=f"{collection_name}-dashboard-name-input",
                                                type="text",
                                                value="New Dashboard",
                                                className="form-control",
                                            ),
                                        ],
                                    ),
                                ],
                            ),
                        ],
                    ),
                ],
            ),
            # Chart controls
            create_chart_controls(collection_name),
            # Dashboard action buttons
            create_dashboard_action_buttons(collection_name),
            # Chart container
            html.Div(id=f"{collection_name}-chart-container"),
        ],
    )
