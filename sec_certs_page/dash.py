# sec_certs_page/dash.py
import dash
from dash import dcc, html

# This is just an example layout from https://dash.plotly.com/urls#example:-simple-multi-page-app-with-pages
# The layout needs to be a callable (it may be defined elsewhere) as the page registry does not contain
# all of the pages yet when this is initialized.
dash.register_page(
    __name__,
    path="/",
    layout=lambda: html.Div(
        [
            html.H1("Multi-page app with Dash Pages"),
            html.Div(
                [
                    html.Div(dcc.Link(f"{page['name']} - {page['path']}", href=page["relative_path"]))
                    for page in dash.page_registry.values()
                ]
            ),
        ]
    ),
)
