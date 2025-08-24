import dash
from dash import html

# By creating the Dash app in init.py with `use_pages=True`,
# Dash will automatically discover this file and register it as a page.
dash.register_page(
    __name__,
    path="/",  # The root URL for the dashboard: `/dashboard/`
    title="sec-certs Interactive Dashboard",
    name="Interactive Dashboard",
)


def layout():
    return html.Div(
        children=[
            html.H1("sec-certs Interactive Dashboard"),
            html.P("This is the main container for the dashboard components."),
            # The DashboardLayoutManager and CallbackManager here
            html.Div(id="dashboard-content"),
        ]
    )
