import plotly.graph_objects as go
from dash import dcc, html

from sec_certs_page.dashboard.chart.chart import Chart
from sec_certs_page.dashboard.data import DataService

from ..base import BaseChart


class CCCertsPerYear(BaseChart):
    """A bar chart showing the number of certificates by category and year."""

    def __init__(self, graph_id: str, data_service: DataService, config: Chart) -> None:
        super().__init__(graph_id, data_service, chart_type="bar", config=config)

    @property
    def title(self) -> str:
        return self.config.title if self.config and self.config.title else "Certificates by Category and Year"

    def render(self, filter_values: dict | None = None) -> html.Div:
        """Render the bar chart with per-chart filter configuration."""
        # Build filter values from chart's active filters
        active_filters = self.config.get_active_filters() if self.config else {}

        # Extract filter values from FilterSpec objects
        chart_filter_values = {fid: fspec.data for fid, fspec in active_filters.items() if fspec.data is not None}

        df = self.data_service.get_cc_dataframe(filter_values=chart_filter_values if chart_filter_values else None)

        if df.empty:
            return self._render_container(
                [
                    *self._render_header(),
                    html.P("No data available", style={"color": "gray", "textAlign": "center"}),
                ]
            )

        # Create figure
        category_per_year = df.groupby(["year_from", "category"]).size().unstack(fill_value=0)
        fig = go.Figure()

        for category in category_per_year.columns:
            fig.add_trace(
                go.Bar(
                    name=category,
                    x=category_per_year.index,
                    y=category_per_year[category],
                )
            )

        # Use config for layout customization
        x_label = self.config.x_axis.label if self.config and self.config.x_axis else "Year"
        y_label = self.config.y_axis.label if self.config and self.config.y_axis else "Number of Certificates"

        fig.update_layout(
            title=self.title,
            barmode="stack",
            xaxis=dict(title=x_label),
            yaxis=dict(title=y_label),
            margin=dict(t=80, l=40, r=40, b=40),
            showlegend=self.config.show_legend if self.config else True,
            colorway=self.config.color_scheme if self.config and self.config.color_scheme else None,
        )

        return self._render_container(
            [
                *self._render_header(),
                self._create_config_store(),
                dcc.Graph(figure=fig, config={"displayModeBar": True}),
            ]
        )
