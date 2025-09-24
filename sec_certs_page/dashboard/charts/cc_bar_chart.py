"""A concrete implementation of a bar chart for CC certificates by manufacturer."""

import plotly.graph_objects as go
from dash import Dash, dcc, html
from dash.dependencies import Input, Output

from .base import BaseGraph


class CCBarChart(BaseGraph):
    """A bar chart showing the number of certificates by category and year."""

    @property
    def title(self) -> str:
        return "Certificates by Category and Year"

    def render(self) -> html.Div:
        """Renders the bar chart component."""
        return html.Div(
            [
                html.H2("Certificates by Category and Year"),
                dcc.Graph(id=self.id),
            ]
        )

    def register_callback(self, app: Dash) -> None:
        """Registers the callback to update the bar chart."""

        @app.callback(
            Output(self.id, "figure"),
            Input(self.id, "id"),  # Dummy input to trigger on page load
        )
        def update_bar_chart(_: str) -> go.Figure:
            """Fetches data and creates the bar chart figure."""
            df = self.data_service.get_cc_dataframe()
            if df.empty:
                return go.Figure()

            category_per_year = df.groupby(["year_from", "category"]).size().unstack(fill_value=0)

            fig = go.Figure()

            for idx, category in enumerate(category_per_year.columns):
                fig.add_trace(
                    go.Bar(
                        name=category,
                        x=category_per_year.index,
                        y=category_per_year[category],
                        marker=dict(color=self.color_palette[idx % len(self.color_palette)]),
                    )
                )

            fig.update_layout(
                title="Certificates grouped by category and year",
                barmode="relative",
                xaxis=dict(title="Year"),
                yaxis=dict(title="Number of Certificates"),
                margin=dict(t=80, l=40, r=40, b=40),
            )
            return fig
