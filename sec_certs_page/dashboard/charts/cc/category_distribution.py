"""A chart showing the distribution of CC certificate categories."""

import plotly.graph_objects as go
from dash import Dash, dcc, html
from dash.dependencies import Input, Output

from sec_certs_page.dashboard.data import DataService

from ..base import BaseChart


class CCCategoryDistribution(BaseChart):
    """A chart showing the distribution of CC certificate categories."""

    def __init__(self, graph_id: str, data_service: DataService):
        super().__init__(graph_id, data_service, chart_type="pie", available_chart_types=["pie", "bar"])

    @property
    def title(self) -> str:
        return "Category Distribution"

    def render(self) -> html.Div:
        """Renders the chart and its associated dropdown filter."""
        return html.Div(
            [
                *self._render_header(),
                dcc.Graph(id=self.id),
            ]
        )

    def register_callback(self, app: Dash) -> None:
        """Registers the callback to update the chart."""
        outputs = Output(self.id, "figure")
        inputs = [
            Input("cc-filter-store", "data"),
            Input(self.chart_type_selector_id, "value"),
        ]

        @app.callback(outputs, inputs)
        def update_chart(filter_data: dict, chart_type: str) -> go.Figure:
            """Fetches data and creates the chart figure."""
            df = self.data_service.get_cc_dataframe()
            if df.empty:
                return go.Figure()
            selected_categories = filter_data.get("cc-category-filter")
            if selected_categories:
                df = df[df["category"].isin(selected_categories)]

            category_counts = df["category"].value_counts()
            fig = go.Figure()

            if chart_type == "pie":
                fig.add_trace(go.Pie(labels=category_counts.index, values=category_counts.values, hole=0.3))
            elif chart_type == "bar":
                fig.add_trace(go.Bar(x=category_counts.index, y=category_counts.values))

            fig.update_layout(
                title="Number of issued certificates by category",
                margin={"t": 80, "l": 40, "r": 40, "b": 40},
                height=700,
            )
            return fig
