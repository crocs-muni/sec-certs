"""Dashboard rendering factory."""

from dash import dcc, html

from sec_certs_page.dashboard.dashboard import Dashboard

from .chart.registry import ChartRegistry
from .types.common import CollectionName


class DashboardFactory:
    """
    Factory for rendering dashboard UI components.

    Responsible for creating the visual representation of a Dashboard,
    including chart controls and chart container. Used by collection pages
    to render the active dashboard content.
    """

    def __init__(self, collection_name: CollectionName):
        """
        Initialize the factory for a specific collection.

        :param collection_name: The collection this factory renders dashboards for
        """
        self.collection_name = collection_name

    def render_dashboard_content(
        self,
        dashboard: Dashboard,
        chart_registry: ChartRegistry,
    ) -> html.Div:
        """
        Render the main dashboard content area with chart controls.

        This creates the content that appears when a dashboard is active,
        including the dashboard name, chart selector, and chart container.

        :param dashboard: The dashboard to render
        :param chart_registry: Chart registry for available charts
        :return: Dash HTML component for the dashboard content
        """
        chart_options = [{"label": chart.title, "value": chart.id} for chart in chart_registry]

        return html.Div(
            children=[
                html.Div(
                    style={"marginBottom": "20px"},
                    children=[
                        html.H3(f"Dashboard: {dashboard.name}"),
                        html.P(
                            f"Analyzing {self.collection_name.value.upper()} data",
                            style={"color": "#666", "margin": "0"},
                        ),
                    ],
                ),
                html.Div(
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
                                    id=f"{self.collection_name}-chart-selector",
                                    options=chart_options,
                                    placeholder="Select a chart to add...",
                                    style={"width": "300px"},
                                ),
                                html.Button(
                                    "Add Chart",
                                    id=f"{self.collection_name}-add-chart-btn",
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
                ),
                html.Div(
                    style={"marginBottom": "20px"},
                    children=[
                        html.Button(
                            "🔄 Update All Charts",
                            id=f"{self.collection_name}-update-all-btn",
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
                            id=f"{self.collection_name}-save-dashboard-btn",
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
                ),
                # Chart container - where rendered charts appear
                html.Div(id=f"{self.collection_name}-chart-container"),
            ]
        )

    def render(
        self,
        dashboard: Dashboard,
        chart_registry: ChartRegistry,
    ) -> html.Div:
        """
        Render a complete dashboard view with all stores and controls.

        This method creates a standalone dashboard view that can be used
        independently of the page structure. Includes all necessary state
        stores for the dashboard to function.

        :param dashboard: The dashboard to render
        :param chart_registry: Chart registry for this dataset
        :return: Dash HTML component for the complete dashboard
        """
        chart_options = [{"label": chart.title, "value": chart.id} for chart in chart_registry]

        return html.Div(
            [
                dcc.Store(id=f"{self.collection_name}-filter-store", data={}),
                dcc.Store(id=f"{self.collection_name}-render-trigger", data=0),
                dcc.Store(id=f"{self.collection_name}-current-dashboard-id", data=str(dashboard.dashboard_id)),
                dcc.Store(id=f"{self.collection_name}-collection-name", data=self.collection_name),
                html.H1(f"Dashboard: {dashboard.name}"),
                html.P(
                    f"{self.collection_name.upper()} data analysis",
                    style={"color": "#666", "marginBottom": "20px"},
                ),
                html.Hr(),
                html.Div(
                    [
                        html.H3("Chart Controls"),
                        html.Div(
                            [
                                dcc.Dropdown(
                                    id=f"{self.collection_name}-chart-selector",
                                    options=chart_options,
                                    placeholder="Select a chart to add...",
                                    style={"width": "300px", "display": "inline-block"},
                                ),
                                html.Button(
                                    "Add Chart",
                                    id=f"{self.collection_name}-add-chart-btn",
                                    n_clicks=0,
                                    style={"display": "inline-block", "marginLeft": "10px"},
                                ),
                            ],
                            style={"marginBottom": "10px"},
                        ),
                        html.Div(
                            [
                                html.Button(
                                    "🔄 Update All Charts",
                                    id=f"{self.collection_name}-update-all-btn",
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
                                    id=f"{self.collection_name}-save-dashboard-btn",
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
                        ),
                    ],
                    style={"marginBottom": "20px"},
                ),
                html.Div(id=f"{self.collection_name}-chart-container"),
            ]
        )
