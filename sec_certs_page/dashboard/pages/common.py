"""Common utilities for dashboard collection pages."""

from dash import dcc, html

from sec_certs_page.dashboard.types.common import CollectionName


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
            html.Div(
                style={"marginBottom": "20px"},
                children=[
                    html.H2(title),
                    dcc.Link("← Back to Home", href="/", style={"color": "#666"}),
                ],
            ),
            # Dashboard management section
            html.Div(
                style={
                    "backgroundColor": "#f8f9fa",
                    "padding": "20px",
                    "borderRadius": "8px",
                    "marginBottom": "20px",
                },
                children=[create_dashboard_management_buttons(prefix)],
            ),
            # Empty state
            create_empty_state(prefix),
            # Dashboard content
            create_dashboard_content(prefix),
        ]
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


def create_dashboard_management_buttons(collection_name: str) -> html.Div:
    """
    Create the dashboard management buttons (Create New, Load Predefined).

    :return: Div containing the action buttons
    """
    return html.Div(
        style={"display": "flex", "alignItems": "center", "gap": "15px", "flexWrap": "wrap"},
        children=[
            html.Div(
                children=[
                    html.Label("Select Dashboard:", style={"fontWeight": "bold", "marginRight": "10px"}),
                    dcc.Dropdown(
                        id=f"{collection_name}-dashboard-selector",
                        options=[],
                        placeholder="Select a saved dashboard...",
                        style={"width": "250px"},
                        clearable=True,
                    ),
                ],
                style={"display": "flex", "alignItems": "center"},
            ),
            html.Button(
                "➕ Create New Dashboard",
                id=f"{collection_name}-create-dashboard-btn",
                n_clicks=0,
                style={
                    "padding": "10px 20px",
                    "fontSize": "14px",
                    "backgroundColor": "#28a745",
                    "color": "white",
                    "border": "none",
                    "borderRadius": "5px",
                    "cursor": "pointer",
                },
            ),
            html.Button(
                "📊 Load Predefined Charts",
                id=f"{collection_name}-load-predefined-btn",
                n_clicks=0,
                style={
                    "padding": "10px 20px",
                    "fontSize": "14px",
                    "backgroundColor": "#007bff",
                    "color": "white",
                    "border": "none",
                    "borderRadius": "5px",
                    "cursor": "pointer",
                },
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
            html.Div(
                style={
                    "textAlign": "center",
                    "padding": "60px 20px",
                    "backgroundColor": "#fff",
                    "borderRadius": "8px",
                    "border": "2px dashed #ddd",
                },
                children=[
                    html.H3("No Dashboard Selected", style={"color": "#666"}),
                    html.P(
                        "Create a new dashboard or select an existing one from the dropdown above.",
                        style={"color": "#999"},
                    ),
                ],
            ),
        ],
    )


def create_chart_controls(collection_name: str) -> html.Div:
    """
    Create the chart selection and control panel.

    :param collection_name: The collection_name for component IDs
    :return: Div containing chart controls
    """
    return html.Div(
        style={
            "backgroundColor": "#fff",
            "padding": "15px",
            "borderRadius": "8px",
            "border": "1px solid #ddd",
            "marginBottom": "20px",
        },
        children=[
            html.H4("Add Charts", style={"marginBottom": "15px"}),
            html.Div(
                style={"display": "flex", "alignItems": "center", "gap": "10px"},
                children=[
                    dcc.Dropdown(
                        id=f"{collection_name}-chart-selector",
                        options=[],
                        placeholder="Select a chart to add...",
                        style={"width": "300px"},
                    ),
                    html.Button(
                        "Add Chart",
                        id=f"{collection_name}-add-chart-btn",
                        n_clicks=0,
                        style={
                            "padding": "8px 16px",
                            "backgroundColor": "#28a745",
                            "color": "white",
                            "border": "none",
                            "borderRadius": "4px",
                            "cursor": "pointer",
                        },
                    ),
                ],
            ),
        ],
    )


def create_dashboard_action_buttons(collection_name: str) -> html.Div:
    """
    Create the dashboard action buttons (Update All, Save).

    :param collection_name: The collection_name for component IDs
    :return: Div containing action buttons
    """
    return html.Div(
        style={"marginBottom": "20px"},
        children=[
            html.Button(
                "🔄 Update All Charts",
                id=f"{collection_name}-update-all-btn",
                n_clicks=0,
                disabled=True,
                style={
                    "marginRight": "10px",
                    "padding": "8px 16px",
                    "backgroundColor": "#4CAF50",
                    "color": "white",
                    "border": "none",
                    "borderRadius": "4px",
                    "cursor": "pointer",
                },
            ),
            html.Button(
                "💾 Save Dashboard",
                id=f"{collection_name}-save-dashboard-btn",
                n_clicks=0,
                disabled=True,
                style={
                    "padding": "8px 16px",
                    "backgroundColor": "#2196F3",
                    "color": "white",
                    "border": "none",
                    "borderRadius": "4px",
                    "cursor": "pointer",
                },
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
            html.Div(
                style={"marginBottom": "20px"},
                children=[
                    html.Label("Dashboard Name:", style={"fontWeight": "bold", "marginRight": "10px"}),
                    dcc.Input(
                        id=f"{collection_name}-dashboard-name-input",
                        type="text",
                        value="New Dashboard",
                        style={"width": "300px", "padding": "8px"},
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
