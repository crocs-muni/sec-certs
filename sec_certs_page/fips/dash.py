import dash
import pandas as pd
import plotly.express as px
from dash import Input, Output, dcc, html

from . import get_fips_standards

dash.register_page(
    __name__,
    name="FIPS 140",
    path="/fips/",
    layout=lambda: html.Div(
        [
            html.H1("This is our FIPS 140 page"),
            html.Div("This is our FIPS 140 page content."),
            dcc.Graph(id="fips-standard-graph"),
        ]
    ),
)


@dash.callback(
    Output("fips-standard-graph", "figure"),
    Input("fips-standard-graph", "id"),  # Dummy input just to trigger at load
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
    fig = px.line(df, x="date", y="count", color="standard", markers=True, title="Documents per Standard per Month")
    return fig
