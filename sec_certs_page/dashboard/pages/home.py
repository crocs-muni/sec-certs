"""Dashboard home page - collection selection."""

import dash
import dash_bootstrap_components as dbc
from dash import html

from ... import DASHBOARD_URL_BASE_PATHNAME
from ..types.common import CollectionName

# Collection metadata for cards
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


def _build_collection_card(collection_name: CollectionName) -> dbc.Col:
    """Build a single collection card."""
    info = _COLLECTION_INFO.get(collection_name, {})
    if not info:
        return dbc.Col()

    return dbc.Col(
        width=12,
        lg=6,
        className="mb-4",
        children=[
            dbc.Card(
                className="h-100 shadow-sm collection-card",
                children=[
                    dbc.CardHeader(
                        className=f"bg-{info['color']} text-white py-4",
                        children=[
                            html.Div(
                                className="d-flex align-items-center",
                                children=[
                                    html.Div(
                                        className="me-3",
                                        children=[
                                            html.I(className=f"{info['icon']} fa-3x"),
                                        ],
                                    ),
                                    html.Div(
                                        children=[
                                            html.H3(info["title"], className="mb-0 fw-bold"),
                                        ],
                                    ),
                                ],
                            ),
                        ],
                    ),
                    dbc.CardBody(
                        className="py-4",
                        children=[
                            html.P(info["description"], className="card-text lead mb-0"),
                        ],
                    ),
                    dbc.CardFooter(
                        className="bg-transparent border-0 pt-0 pb-4 px-4",
                        children=[
                            dbc.Button(
                                [
                                    "Open Dashboard",
                                    html.I(className="fas fa-arrow-right ms-2"),
                                ],
                                href=f"{DASHBOARD_URL_BASE_PATHNAME}{collection_name}",
                                color=info["color"],
                                size="lg",
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
        className="py-4",
        children=[
            # Welcome section
            dbc.Row(
                className="mb-4",
                children=[
                    dbc.Col(
                        width=12,
                        children=[
                            html.H1("Certificate Analysis Dashboard", className="mb-2 fw-bold"),
                            html.P(
                                "Select a certificate dataset below to create interactive visualizations and explore certification trends.",
                                className="lead text-muted mb-0",
                            ),
                        ],
                    ),
                ],
            ),
            # Collection cards
            dbc.Row(
                className="g-4 mb-5",
                children=_build_collection_cards(),
            ),
            # Getting started section
            dbc.Card(
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
                        children=[
                            dbc.Row(
                                className="g-4",
                                children=[
                                    dbc.Col(
                                        width=12,
                                        md=6,
                                        lg=True,
                                        children=[
                                            html.Div(
                                                className="d-flex align-items-start",
                                                children=[
                                                    html.Span(
                                                        "1",
                                                        className="badge bg-primary rounded-circle me-3 fs-6",
                                                    ),
                                                    html.Span(
                                                        "Choose a certificate collection (CC or FIPS)",
                                                        className="text-muted",
                                                    ),
                                                ],
                                            ),
                                        ],
                                    ),
                                    dbc.Col(
                                        width=12,
                                        md=6,
                                        lg=True,
                                        children=[
                                            html.Div(
                                                className="d-flex align-items-start",
                                                children=[
                                                    html.Span(
                                                        "2",
                                                        className="badge bg-primary rounded-circle me-3 fs-6",
                                                    ),
                                                    html.Span(
                                                        "Create a new dashboard or load an existing one",
                                                        className="text-muted",
                                                    ),
                                                ],
                                            ),
                                        ],
                                    ),
                                    dbc.Col(
                                        width=12,
                                        md=6,
                                        lg=True,
                                        children=[
                                            html.Div(
                                                className="d-flex align-items-start",
                                                children=[
                                                    html.Span(
                                                        "3",
                                                        className="badge bg-primary rounded-circle me-3 fs-6",
                                                    ),
                                                    html.Span(
                                                        "Add predefined or custom charts",
                                                        className="text-muted",
                                                    ),
                                                ],
                                            ),
                                        ],
                                    ),
                                    dbc.Col(
                                        width=12,
                                        md=6,
                                        lg=True,
                                        children=[
                                            html.Div(
                                                className="d-flex align-items-start",
                                                children=[
                                                    html.Span(
                                                        "4",
                                                        className="badge bg-primary rounded-circle me-3 fs-6",
                                                    ),
                                                    html.Span(
                                                        "Save your dashboard for later use",
                                                        className="text-muted",
                                                    ),
                                                ],
                                            ),
                                        ],
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
