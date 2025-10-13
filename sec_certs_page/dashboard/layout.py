import dash
from dash import dcc, html

from .data import DataService


class DashboardLayoutManager:
    """Manages the creation and structure of the dashboard's app shell."""

    def __init__(self, data_service: DataService):
        self.data_service = data_service

    def build_layout(self) -> html.Div:
        """Constructs the main layout (app shell) of the dashboard."""
        print("Building main dashboard layout...")
        return html.Div(
            [
                html.H1("sec-certs.org Data Dashboards"),
                # --- NAVIGATION ---
                html.Nav(
                    [
                        dcc.Link("CC Dashboard", href="/dashboard/cc", style={"marginRight": "20px"}),
                        dcc.Link("FIPS Dashboard", href="/dashboard/fips"),
                    ]
                ),
                html.Hr(),
                # --- PAGE CONTENT ---
                dash.page_container,
                html.Hr(),
                html.Footer("Dashboard Footer"),
            ]
        )

    def register_home_page(self) -> None:
        """Registers the home page of the dashboard."""
        print("Registering dashboard home page at path=/")

        def home_layout():
            return html.Div(
                [
                    html.H1("Welcome to sec-certs.org Data Dashboards"),
                    html.P("Select a dashboard from the navigation above:"),
                    html.Ul(
                        [
                            html.Li(html.A("Common Criteria Dashboard", href="/dashboard/cc")),
                            html.Li(html.A("FIPS Dashboard", href="/dashboard/fips")),
                        ]
                    ),
                ]
            )

        dash.register_page(
            "dashboard_home", path="/", title="Dashboard Home", name="Dashboard Home", layout=home_layout
        )
        print("✓ Dashboard home page registered successfully")
