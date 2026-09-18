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
                className="feature-card shadow-sm h-100",
                children=[
                    dbc.CardBody(
                        className="d-flex flex-column p-3 p-lg-4",
                        children=[
                            html.Div(
                                className="d-flex align-items-center gap-2 mb-2",
                                children=[
                                    html.Span(
                                        className="feature-icon-chip",
                                        children=html.I(className=f"{info['icon']} fa-fw"),
                                    ),
                                    html.H3(info["title"]),
                                ],
                            ),
                            html.P(info["description"], className="text-body-secondary"),
                            html.Div(
                                className="mt-auto pt-3",
                                children=html.A(
                                    ["Open dashboard ", html.I(className="fas fa-arrow-right fa-xs ms-1")],
                                    href=f"{DASHBOARD_URL_BASE_PATHNAME}{collection_name.value}",
                                    className="fw-semibold text-decoration-none",
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
        className="feature-card shadow-sm mt-3",
        children=[
            dbc.CardBody(
                className="p-3 p-lg-4",
                children=[
                    html.Div(
                        className="d-flex align-items-center gap-2 mb-2",
                        children=[
                            html.Span(
                                className="feature-icon-chip",
                                children=html.I(className="fas fa-lightbulb fa-fw"),
                            ),
                            html.H3("Getting started"),
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
            html.Div(
                className="home-container px-3 px-md-4 pt-md-4 pb-3",
                children=[
                    dbc.Row(
                        children=[
                            dbc.Col(
                                width=12,
                                children=[
                                    html.H1("Dashboards", className="h2 mb-3"),
                                    html.P(
                                        "Select a certificate dataset below to create interactive visualizations and explore certification trends.",
                                        className="text-body mb-0",
                                    ),
                                ],
                            ),
                        ],
                    ),
                ],
            ),
            # Collection cards
            html.Div(
                className="home-band pt-3 pb-3 pb-md-4",
                children=[
                    html.Div(
                        className="home-container px-3 px-md-4",
                        children=[
                            html.H2("Choose a collection", className="h5 mb-3"),
                            dbc.Row(
                                className="g-3 row-cols-1 row-cols-md-2",
                                children=_build_collection_cards(),
                            ),
                            _build_getting_started(),
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
