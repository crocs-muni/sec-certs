"""Dashboard home page - collection selection."""

import dash
from dash import dcc, html

from .types.common import CollectionName


def _build_collection_cards() -> list[html.Div]:
    """
    Build clickable cards for each available collection.

    Each card links to the respective collection's dashboard page.
    """
    cards = []

    collection_info = {
        CollectionName.CommonCriteria: {
            "title": "Common Criteria (CC)",
            "description": "Explore Common Criteria security certificates and their analysis.",
            "color": "#2196F3",
        },
        CollectionName.FIPS140: {
            "title": "FIPS 140",
            "description": "Analyze FIPS 140 cryptographic module validations.",
            "color": "#4CAF50",
        },
    }

    for collection_name in CollectionName:
        info = collection_info.get(
            collection_name,
            {"title": collection_name.value.upper(), "description": "", "color": "#666"},
        )

        card = html.Div(
            style={
                "border": "2px solid #ddd",
                "borderRadius": "12px",
                "padding": "30px",
                "margin": "15px",
                "width": "320px",
                "textAlign": "center",
                "backgroundColor": "#fff",
                "boxShadow": "0 2px 8px rgba(0,0,0,0.1)",
                "transition": "transform 0.2s, box-shadow 0.2s",
            },
            children=[
                html.H2(
                    info["title"],
                    style={"color": info["color"], "marginBottom": "15px"},
                ),
                html.P(
                    info["description"],
                    style={"color": "#666", "marginBottom": "20px", "minHeight": "50px"},
                ),
                dcc.Link(
                    "Open Dashboard →",
                    href=f"/{collection_name.value}",
                    style={
                        "display": "inline-block",
                        "padding": "12px 24px",
                        "backgroundColor": info["color"],
                        "color": "white",
                        "textDecoration": "none",
                        "borderRadius": "6px",
                        "fontWeight": "bold",
                        "fontSize": "14px",
                    },
                ),
            ],
        )
        cards.append(card)

    return cards


def layout(**kwargs) -> html.Div:
    """Home page layout - shows available collections to choose from."""
    return html.Div(
        children=[
            # Welcome section
            html.Div(
                style={"textAlign": "center", "marginBottom": "40px"},
                children=[
                    html.H1(
                        "Welcome to the Dashboard",
                        style={"marginBottom": "10px"},
                    ),
                    html.P(
                        "Select a dataset to create or load dashboards for data analysis.",
                        style={"fontSize": "18px", "color": "#666"},
                    ),
                ],
            ),
            # Collection cards
            html.Div(
                style={
                    "display": "flex",
                    "flexWrap": "wrap",
                    "justifyContent": "center",
                    "marginTop": "20px",
                },
                children=_build_collection_cards(),
            ),
            # Getting started section
            html.Hr(style={"marginTop": "50px"}),
            html.Div(
                style={"marginTop": "30px", "color": "#666", "maxWidth": "600px", "margin": "30px auto"},
                children=[
                    html.H3("Getting Started", style={"textAlign": "center"}),
                    html.Ol(
                        children=[
                            html.Li("Select a dataset (CC or FIPS) from the cards above"),
                            html.Li("Create a new dashboard or load an existing one"),
                            html.Li("Add charts to visualize certificate data"),
                            html.Li("Apply filters to focus on specific data"),
                            html.Li("Save your dashboard configuration for later use"),
                        ],
                        style={"lineHeight": "2"},
                    ),
                ],
            ),
        ]
    )


dash.register_page(
    "home",
    path="/",
    title="Dashboard Home",
    name="Dashboard Home",
    layout=layout,
)
