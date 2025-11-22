import dash
from dash import dcc, html

from sec_certs_page.dashboard.types.common import CollectionName

from .data import DataService


class DashboardLayout:
    """Manages the creation and structure of the dashboard's app shell."""

    def __init__(self, data_service: DataService):
        self.data_service = data_service

    def create(self) -> html.Div:
        """Construct the main layout (app shell) of the dashboard."""

        nav_links = []
        for i, dataset_type in enumerate(CollectionName):
            if i > 0:
                nav_links.append(html.Span(" | ", style={"margin": "0 10px"}))
            nav_links.append(
                dcc.Link(
                    f"{dataset_type.value.upper()} Dashboard",
                    href=f"/{dataset_type.value}",
                    style={"textDecoration": "none"},
                )
            )

        return html.Div(
            style={"maxWidth": "1400px", "margin": "0 auto", "padding": "20px"},
            children=[
                html.Header(
                    style={
                        "borderBottom": "2px solid #eee",
                        "paddingBottom": "15px",
                        "marginBottom": "20px",
                    },
                    children=[
                        html.H1(
                            "sec-certs.org Data Dashboards",
                            style={"margin": "0 0 10px 0"},
                        ),
                        html.Nav(
                            nav_links,
                            style={"display": "flex", "alignItems": "center"},
                        ),
                    ],
                ),
                dash.page_container,
                html.Footer(
                    style={
                        "borderTop": "1px solid #eee",
                        "paddingTop": "15px",
                        "marginTop": "30px",
                        "color": "#666",
                        "fontSize": "14px",
                    },
                    children=[
                        html.A(
                            "Documentation",
                            href="https://sec-certs.org/docs",
                            target="_blank",
                            style={"marginRight": "20px"},
                        ),
                        html.A(
                            "sec-certs.org",
                            href="https://sec-certs.org",
                            target="_blank",
                        ),
                    ],
                ),
            ],
        )

    def dashboard_cards(self):
        dashboard_cards = []
        for dt in CollectionName:
            card = html.Div(
                style={
                    "border": "1px solid #ddd",
                    "borderRadius": "8px",
                    "padding": "20px",
                    "margin": "10px",
                    "width": "300px",
                    "textAlign": "center",
                },
                children=[
                    html.H3(f"{dt.value.upper()} Dashboard"),
                    html.P(f"Interactive analysis for {dt.value.upper()} certificates"),
                    dcc.Link(
                        "Open Dashboard →",
                        href=f"/{dt.value}",
                        style={
                            "display": "inline-block",
                            "padding": "10px 20px",
                            "color": "white",
                            "textDecoration": "none",
                            "borderRadius": "5px",
                            "marginTop": "10px",
                        },
                    ),
                ],
            )
            dashboard_cards.append(card)
        return dashboard_cards

    def home_layout(self) -> html.Div:
        """Layout for the dashboard home page."""
        return html.Div(
            children=[
                html.H1("Welcome to sec-certs.org Data Dashboards"),
                html.P(
                    "Select a dashboard to explore security certification data:",
                    style={"fontSize": "18px", "color": "#666"},
                ),
                html.Div(
                    style={
                        "display": "flex",
                        "flexWrap": "wrap",
                        "justifyContent": "center",
                        "marginTop": "30px",
                    },
                    children=self.dashboard_cards(),
                ),
                html.Hr(style={"marginTop": "40px"}),
                html.Div(
                    style={"marginTop": "20px", "color": "#666"},
                    children=[
                        html.H3("Getting Started"),
                        html.P("1. Select a dataset type (CC or FIPS) from the cards above"),
                        html.P("2. Use filters to narrow down the data"),
                        html.P("3. Add charts to visualize different aspects"),
                        html.P("4. Save your dashboard configuration for later use"),
                    ],
                ),
            ]
        )

    def register_home_page(self) -> None:
        """Register the home page of the dashboard."""

        dash.register_page(
            "dashboard_home",
            path="/",
            title="Dashboard Home",
            name="Dashboard Home",
            layout=self.home_layout,
        )
        print("✓ Dashboard home page registered")
