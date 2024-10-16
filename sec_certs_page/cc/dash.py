import dash
from dash import html

dash.register_page(
    __name__,
    name="CC",
    path="/cc/",
    layout=lambda: html.Div(
        [
            html.H1("This is our CC page"),
            html.Div("This is our CC page content."),
        ]
    ),
)
