"""Dashboard rendering factory."""

from dash import dcc, html

from sec_certs_page.dashboard.dashboard import Dashboard
from sec_certs_page.dashboard.dependencies import ComponentID, ComponentIDBuilder

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

        store_id = ComponentIDBuilder(self.collection_name)
        return html.Div(
            [
                dcc.Store(id=store_id(ComponentID.FILTER_STORE), data={}),
                dcc.Store(id=store_id(ComponentID.RENDER_TRIGGER), data=0),
                dcc.Store(id=store_id(ComponentID.CURRENT_DASHBOARD_ID), data=str(dashboard.dashboard_id)),
                dcc.Store(id=store_id(ComponentID.COLLECTION_NAME), data=self.collection_name),
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
