import dash
import pandas as pd
import plotly.express as px
from dash import Input, Output, dcc, html

from ..fips import get_fips_standards


def register_pages():
    """Register all FIPS dashboard pages with Dash."""

    def layout():
        """Defines the layout for the FIPS dashboard page."""
        return html.Div(
            [
                html.H1("This is our FIPS 140 page"),
                html.Div("This is our FIPS 140 page content."),
                dcc.Graph(id="fips-standard-graph"),
            ]
        )

    dash.register_page(
        __name__,
        path="/fips",
        title="FIPS Dashboard",
        name="FIPS Dashboard",
        layout=layout,
    )

    @dash.callback(
        Output("fips-standard-graph", "figure"),
        Input("fips-standard-graph", "id"),
    )
    def update_fips_standards(_):
        # Now this runs per-request/user, and you can safely fetch data here!
        data = []
        for entry in get_fips_standards():
            standard = entry["_id"]["standard"]
            year = entry["_id"]["year"]
            month = entry["_id"]["month"]
            count = entry["count"]
            # You can create a datetime or just use year/month as string
            if year is None or month is None:
                continue
            date = pd.Timestamp(year=year, month=month, day=1)
            data.append({"standard": standard, "date": date, "count": count})

        df = pd.DataFrame(data)

        # Plot: x = date, y = count, color = standard
        fig = px.line(
            df,
            x="date",
            y="count",
            color="standard",
            markers=True,
            title="Documents per Standard per Month",
        )
        return fig
