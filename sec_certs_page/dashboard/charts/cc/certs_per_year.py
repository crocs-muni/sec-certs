"""A concrete implementation of a bar chart for CC certificates per year."""

import plotly.graph_objects as go
from dash import Dash, dcc, html
from dash.dependencies import Input, Output

from sec_certs_page.dashboard.data import DataService

from ..base import BaseChart


class CCCertsPerYear(BaseChart):
    """A bar chart showing the number of certificates by category and year."""

    def __init__(self, graph_id: str, data_service: DataService):
        super().__init__(graph_id, data_service, chart_type="bar", available_chart_types=["bar"])

    @property
    def title(self) -> str:
        return "Certificates by Category and Year"

    def render(self) -> html.Div:
        """Renders the bar chart component."""
        return html.Div(
            [
                *self._render_header(),
                dcc.Graph(id=self.id),
            ]
        )

    def register_callback(self, app: Dash) -> None:
        """Registers the callback to update the bar chart."""

        @app.callback(
            Output(self.id, "figure"),
            Input("cc-filter-store", "data"),
        )
        def update_bar_chart(filter_data: dict) -> go.Figure:
            """Fetches data and creates the bar chart figure."""
            df = self.data_service.get_cc_dataframe()
            if df.empty:
                return go.Figure()

            # Apply filters from the central store
            selected_categories = filter_data.get("category-filter")  # Standard filter ID from CCFilterRegistry
            if selected_categories:
                df = df[df["category"].isin(selected_categories)]

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
                barmode="stack",
                xaxis=dict(title="Year"),
                yaxis=dict(title="Number of Certificates"),
                margin=dict(t=80, l=40, r=40, b=40),
            )
            return fig
