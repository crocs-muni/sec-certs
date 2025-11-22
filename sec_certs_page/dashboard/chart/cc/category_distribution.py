import plotly.graph_objects as go
from dash import dcc, html

from sec_certs_page.dashboard.chart.base import BaseChart
from sec_certs_page.dashboard.chart.chart import Chart
from sec_certs_page.dashboard.data import DataService


class CCCategoryDistribution(BaseChart):
    """A chart showing the distribution of CC certificate categories."""

    def __init__(self, graph_id: str, data_service: DataService, config: Chart) -> None:
        super().__init__(
            graph_id=graph_id,
            data_service=data_service,
            chart_type="pie",
            config=config,
        )

    @property
    def title(self) -> str:
        return self.config.title if self.config and self.config.title else "Category Distribution"

    def render(self) -> html.Div:
        """Render the chart with per-chart filter configuration."""
        active_filters = self.config.get_active_filters() if self.config else {}

        chart_filter_values = {fid: fspec.data for fid, fspec in active_filters.items() if fspec.data is not None}

        df = self.data_service.get_cc_dataframe(filter_values=chart_filter_values if chart_filter_values else None)

        if df.empty:
            return self._render_container(
                [
                    *self._render_header(),
                    html.P("No data available", style={"color": "gray", "textAlign": "center"}),
                ]
            )

        category_counts = df["category"].value_counts()
        fig = go.Figure()

        fig.add_trace(
            go.Pie(
                labels=category_counts.index,
                values=category_counts.values,
                hole=0.3,
            )
        )
        fig.update_layout(
            title=self.title,
            margin={"t": 80, "l": 40, "r": 40, "b": 40},
            height=500,
            showlegend=self.config.show_legend if self.config else True,
        )

        return self._render_container(
            [
                *self._render_header(),
                self._create_config_store(),
                dcc.Graph(figure=fig, config={"displayModeBar": True}),
            ]
        )
