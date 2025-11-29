"""Dashboard home page - collection selection."""

import dash
import dash_bootstrap_components as dbc
from dash import html

from ... import DASHBOARD_URL_BASE_PATHNAME
from ..types.common import CollectionName

# Collection metadata for cards
_COLLECTION_INFO = {
    CollectionName.CommonCriteria.value: {
        "title": "Common Criteria",
        "description": "Explore and analyze Common Criteria security certificates, including EAL levels, categories, and certification trends.",
        "icon": "fas fa-shield-alt",
        "color": "primary",
    },
    CollectionName.FIPS140.value: {
        "title": "FIPS 140",
        "description": "Analyze FIPS 140 cryptographic module validations, security levels, and vendor certifications.",
        "icon": "fas fa-lock",
        "color": "success",
    },
}


def _build_collection_card(collection_name: str) -> dbc.Col:
    """Build a single collection card."""
    info = _COLLECTION_INFO.get(collection_name, {})
    if not info:
        return dbc.Col()

    return dbc.Col(
        width=12,
        md=6,
        lg=5,
        className="mb-4",
        children=[
            dbc.Card(
                className="h-100 shadow-sm",
                children=[
                    dbc.CardHeader(
                        className=f"bg-{info['color']} text-white",
                        children=[
                            html.I(className=f"{info['icon']} fa-2x me-3"),
                            html.H3(info["title"], className="d-inline mb-0"),
                        ],
                    ),
                    dbc.CardBody(
                        children=[
                            html.P(info["description"], className="card-text lead"),
                        ],
                    ),
                    dbc.CardFooter(
                        className="bg-transparent border-0",
                        children=[
                            dbc.Button(
                                [
                                    "Open Dashboard ",
                                    html.I(className="fas fa-arrow-right ms-2"),
                                ],
                                href=f"{DASHBOARD_URL_BASE_PATHNAME}{collection_name}",
                                color=info["color"],
                                className="w-100",
                                external_link=False,
                            ),
                        ],
                    ),
                ],
            ),
        ],
    )


def _build_collection_cards() -> list[dbc.Col]:
    """Build all collection cards."""
    return [_build_collection_card(name) for name in _COLLECTION_INFO]


def layout(**kwargs) -> html.Div:
    """Home page layout - shows available collections to choose from."""
    return html.Div(
        children=[
            # Welcome section
            dbc.Row(
                className="mb-5",
                children=[
                    dbc.Col(
                        width=12,
                        children=[
                            html.H1("Data Dashboards", className="mb-3"),
                            html.P(
                                "Select a dataset to create or load dashboards for interactive data analysis.",
                                className="lead text-muted",
                            ),
                        ],
                    ),
                ],
            ),
            # Collection cards
            dbc.Row(
                className="g-4",
                children=_build_collection_cards(),
            ),
            # Getting started section
            html.Hr(className="my-5"),
            dbc.Card(
                className="bg-light",
                children=[
                    dbc.CardHeader(
                        html.H4(
                            [html.I(className="fas fa-info-circle me-2"), "Getting Started"],
                            className="mb-0",
                        ),
                    ),
                    dbc.CardBody(
                        children=[
                            html.Ol(
                                className="mb-0",
                                children=[
                                    html.Li(
                                        "Select a dataset (CC or FIPS) from the cards above",
                                        className="mb-2",
                                    ),
                                    html.Li(
                                        "Create a new dashboard or load an existing one",
                                        className="mb-2",
                                    ),
                                    html.Li(
                                        "Add charts to visualize certificate data",
                                        className="mb-2",
                                    ),
                                    html.Li(
                                        "Apply filters to focus on specific data",
                                        className="mb-2",
                                    ),
                                    html.Li(
                                        "Save your dashboard configuration for later use",
                                    ),
                                ],
                            ),
                        ],
                    ),
                ],
            ),
        ],
    )


dash.register_page(
    __name__,
    path="/",
    title="Dashboard Home",
    name="Dashboard Home",
    layout=layout,
)
