import dash
from dash import html


def register_pages():
    """Register all FIPS dashboard pages with Dash."""

    def layout():
        """Defines the layout for the FIPS dashboard page."""
        return html.Div(
            [html.H1("FIPS 140-2/3 Interactive Dashboard"), html.P("This is the placeholder for the FIPS dashboard.")]
        )

    dash.register_page(
        __name__,
        path="/fips",
        title="FIPS Dashboard",
        name="FIPS Dashboard",
        layout=layout,
    )
