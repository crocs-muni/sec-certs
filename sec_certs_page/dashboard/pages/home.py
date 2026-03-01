"""Dashboard home page - collection selection."""

import dash
import dash_bootstrap_components as dbc
from dash import html

from ... import DASHBOARD_URL_BASE_PATHNAME
from ..types.common import CollectionName
from .components import steps_row

_COLLECTION_INFO = {
    CollectionName.CommonCriteria: {
        "title": "Common Criteria",
        "description": "Explore and analyze Common Criteria security certificates, including EAL levels, categories, and certification trends.",
        "icon": "fas fa-shield-alt",
        "color": "primary",
    },
    CollectionName.FIPS140: {
        "title": "FIPS 140",
        "description": "Analyze FIPS 140 cryptographic module validations, security levels, and vendor certifications.",
        "icon": "fas fa-lock",
        "color": "success",
    },
}

_GETTING_STARTED_STEPS = [
    "Choose a certificate collection (CC or FIPS)",
    "Create a new dashboard or load an existing one",
    "Add predefined or custom charts",
    "Save your dashboard for later use",
]


def _build_collection_card(collection_name: CollectionName) -> dbc.Col:
    """Build a single collection card.

    :param collection_name: The collection enum value
    :return: Column containing the card
    """
    info = _COLLECTION_INFO.get(collection_name)
    if not info:
        return dbc.Col()

    return dbc.Col(
        width=12,
        md=6,
        children=[
            html.Div(
                className="feature-icon bg-primary bg-gradient",
                children=html.I(className=f"fas fa-fw fa-chart-line"),
            ),
            html.H2(info["title"]),
            html.P(info["description"]),
            dbc.Button(
                ["Open Dashboard", html.I(className="fas fa-arrow-right ms-2")],
                href=f"{DASHBOARD_URL_BASE_PATHNAME}{collection_name.value}",
                external_link=False,
            ),
        ],
    )


def _build_collection_cards() -> list[dbc.Col]:
    """Build all collection cards.

    :return: List of column components containing cards
    """
    return [_build_collection_card(name) for name in _COLLECTION_INFO]


def _build_getting_started() -> dbc.Card:
    """Build the getting started section.

    :return: Card containing getting started steps
    """
    return dbc.Card(
        className="border-0 bg-light",
        children=[
            dbc.CardHeader(
                className="bg-transparent border-0 pb-0",
                children=[
                    html.H5(
                        [html.I(className="fas fa-lightbulb me-2 text-warning"), "Getting Started"],
                        className="mb-0 text-muted",
                    ),
                ],
            ),
            dbc.CardBody(
                className="pt-3",
                children=[steps_row(_GETTING_STARTED_STEPS)],
            ),
        ],
    )


def layout(**kwargs) -> html.Div:
    """Home page layout - shows available collections to choose from.

    :return: Page layout component
    """
    return html.Div(
        children=[
            # Welcome section
            dbc.Col(
                width=12,
                sm=10,
                className="mx-auto p-3 py-md-5",
                children=[
                    dbc.Row(
                        className="mb-4",
                        children=[
                            dbc.Col(
                                width=12,
                                children=[
                                    html.H1("Dashboards", className="mb-2 fw-bold"),
                                    html.P(
                                        "Select a certificate dataset below to create interactive visualizations and explore certification trends.",
                                        className="lead text-muted mb-0",
                                    ),
                                ],
                            ),
                        ],
                    ),
                ],
            ),
            # Collection cards
            dbc.Row(
                className="bg-darker-light p-3",
                children=[
                    dbc.Col(
                        width=12,
                        sm=10,
                        className="mx-auto",
                        children=[
                            dbc.Row(
                                className="my-5",
                                children=_build_collection_cards(),
                            )
                        ],
                    )
                ],
            ),
            # Getting started section
            html.Div(
                className="col-12 col-sm-10 mx-auto p-3 py-md-5",
                children=[
                    _build_getting_started(),
                ],
            ),
        ]
    )


dash.register_page(
    __name__,
    path="/",
    title="Dashboard Home",
    name="Dashboard Home",
    layout=layout,
)
