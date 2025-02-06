import dash
import plotly.express as px
from dash import dcc, html

from . import get_cc_analysis

dash.register_page(
    __name__,
    name="CC",
    path="/cc/",
    layout=lambda: html.Div(
        [
            html.H1("This is our CC page"),
            html.Div("This is our CC page content."),
            dcc.Graph(
                figure=px.pie(
                    get_cc_analysis()["categories"],
                    title="Certificates by category",
                    names="name",
                    values="value",
                    labels={"value": "count"},
                )
            ),
        ]
    ),
)
