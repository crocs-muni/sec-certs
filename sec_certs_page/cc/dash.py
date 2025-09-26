import dash
import plotly.express as px
from dash import Input, Output, dcc, html

from . import get_cc_categories

dash.register_page(
    __name__,
    name="CC",
    path="/cc/",
    layout=lambda: html.Div(
        [
            html.H1("This is our CC page"),
            html.Div("This is our CC page content."),
            dcc.Graph(id="cc-category-graph"),
        ]
    ),
)


@dash.callback(
    Output("cc-category-graph", "figure"),
    Input("cc-category-graph", "id"),  # Dummy input just to trigger at load
)
def update_cc_categories(_):
    # Now this runs per-request/user, and you can safely fetch data here!
    df = get_cc_categories()
    fig = px.pie(
        df,
        title="Certificates by category",
        names="name",
        values="value",
        labels={"value": "count"},
    )
    return fig
