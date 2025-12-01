from typing import Any

import plotly.express as px
from dash.development.base_component import Component

from ...chart.chart import Chart
from ...data import DataService
from ..base import BaseChart


class CCCertsPerYear(BaseChart):
    """A stacked bar chart showing certificates by category and year."""

    def __init__(self, graph_id: str, data_service: DataService, config: Chart) -> None:
        super().__init__(graph_id, data_service, chart_type="bar", config=config)

    @property
    def title(self) -> str:
        return self.config.title if self.config and self.config.title else "Certificates by Category and Year"

    def render(self, filter_values: dict[str, Any] | None = None) -> Component:
        """Render the stacked bar chart."""
        merged_filters = self._get_merged_filter_values(filter_values)

        df = self.data_service.get_cc_dataframe(filter_values=merged_filters if merged_filters else None)

        if df.empty:
            return self._render_container([self._render_empty_state()])

        # Aggregate by year and category
        category_per_year = df.groupby(["year_from", "category"], observed=True).size().reset_index(name="count")

        x_label = self.config.x_axis.label if self.config and self.config.x_axis else "Year"
        y_label = self.config.y_axis.label if self.config and self.config.y_axis else "Number of Certificates"

        fig = px.bar(
            category_per_year,
            x="year_from",
            y="count",
            color="category",
            barmode="stack",
            labels={
                "year_from": x_label,
                "count": y_label,
                "category": "Category",
            },
        )

        fig.update_layout(
            margin=dict(t=40, l=60, r=40, b=60),
            height=600,
            showlegend=self.config.show_legend if self.config else True,
            template=self.config.color_scheme if self.config and self.config.color_scheme else None,
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        )

        return self._render_container(
            [
                self._create_config_store(),
                self._create_graph_component(figure=fig),
            ]
        )
