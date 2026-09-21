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
    },
    CollectionName.FIPS140: {
        "title": "FIPS 140",
        "description": "Analyze FIPS 140 cryptographic module validations, security levels, and vendor certifications.",
        "icon": "fas fa-lock",
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
            dbc.Card(
                className="h-100",
                children=[
                    dbc.CardBody(
                        className="d-flex flex-column",
                        children=[
                            html.Div(
                                className="d-flex align-items-center gap-3 mb-3",
                                children=[
                                    html.Div(
                                        className="feature-icon-sm bg-primary bg-gradient",
                                        children=html.I(className=f"{info['icon']} fa-fw"),
                                    ),
                                    html.H3(info["title"], className="h5 mb-0"),
                                ],
                            ),
                            html.P(info["description"], className="flex-grow-1"),
                            html.Div(
                                dbc.Button(
                                    ["Open Dashboard ", html.I(className="fas fa-arrow-right ms-1")],
                                    href=f"{DASHBOARD_URL_BASE_PATHNAME}{collection_name.value}",
                                    external_link=True,
                                    color="primary",
                                ),
                            ),
                        ],
                    ),
                ],
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
        children=[
            dbc.CardBody(
                className="p-4",
                children=[
                    html.Div(
                        className="d-flex align-items-center gap-3 mb-3",
                        children=[
                            html.Div(
                                className="feature-icon-sm bg-primary bg-gradient",
                                children=html.I(className="fas fa-lightbulb fa-fw"),
                            ),
                            html.H3("Getting Started", className="h5 mb-0"),
                        ],
                    ),
                    steps_row(_GETTING_STARTED_STEPS),
                ],
            ),
        ],
    )


def layout(**kwargs) -> html.Div:
    """Home page layout - shows available collections to choose from.

    :return: Page layout component
    """
    return html.Div(
        className="scheme-home",
        children=[
            # Welcome section
            dbc.Col(
                width=12,
                sm=10,
                className="mx-auto p-3 pt-md-5",
                children=[
                    dbc.Row(
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
            html.Div(
                className="row p-3",
                children=[
                    html.Div(
                        className="col-12 col-sm-10 mx-auto",
                        children=[
                            dbc.Row(
                                className="g-4 py-3 py-md-4 row-cols-1 row-cols-lg-2",
                                children=_build_collection_cards(),
                            ),
                        ],
                    ),
                ],
            ),
            # Getting started section
            html.Div(
                className="col-12 col-sm-10 mx-auto p-3 pb-md-5",
                children=[
                    _build_getting_started(),
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
