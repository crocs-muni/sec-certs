"""A concrete implementation of a pie chart for CC certificate categories."""

import plotly.graph_objects as go
from dash import Dash, dcc, html
from dash.dependencies import Input, Output

from .base import BaseGraph


class CCPieChart(BaseGraph):
    """A pie chart showing the distribution of CC certificate categories."""

    @property
    def title(self) -> str:
        return "Category Distribution"

    def render(self) -> html.Div:
        """Renders the pie chart and its associated dropdown filter."""
        return html.Div(
            [
                html.H2("Category Distribution"),
                dcc.Graph(id=self.id),
            ]
        )

    def register_callback(self, app: Dash) -> None:
        """Registers the callback to update the pie chart."""

        @app.callback(
            Output(self.id, "figure"),
            Input(self.id, "id"),
        )
        def update_pie_chart(_: str) -> go.Figure:
            """Fetches data and creates the pie chart figure."""
            df = self.data_service.get_cc_dataframe()
            if df.empty:
                return go.Figure()

            category_counts = df["category"].value_counts()

            fig = go.Figure(
                data=[
                    go.Pie(
                        labels=category_counts.index,
                        values=category_counts.values,
                        hole=0.3,
                    )
                ]
            )
            fig.update_layout(
                title="Number of issued certificates by category",
                margin={"t": 80, "l": 40, "r": 40, "b": 40},
                height=700,
            )
            return fig
