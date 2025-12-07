from typing import Any

import plotly.express as px
from dash.development.base_component import Component

from ...chart.chart import ChartConfig
from ...data import DataService
from ..base import BaseChart


class CCCertsPerYear(BaseChart):
    """A stacked bar chart showing certificates by category and year."""

    def __init__(self, config: ChartConfig) -> None:
        super().__init__(config=config)

    @property
    def title(self) -> str:
        return self.config.title if self.config and self.config.title else "Certificates by Category and Year"

    def render(self, data_service: DataService | None = None, filter_values: dict[str, Any] | None = None) -> Component:
        """Render the stacked bar chart."""
        if not data_service:
            return self._render_container([self._render_error_state("Data service not provided")])

        merged_filters = self._get_merged_filter_values(filter_values)

        df = data_service.get_cc_dataframe(filter_values=merged_filters if merged_filters else None)

        if df.empty:
            return self._render_container([self._render_empty_state()])

        # Aggregate by year and category
        x_field = self.config.x_axis.field
        category_per_year = df.groupby([x_field, "category"], observed=True).size().reset_index(name="count")

        x_label = self.config.x_axis.label
        y_label = self.config.y_axis.label if self.config.y_axis else "Count"

        fig = px.bar(
            category_per_year,
            x=x_field,
            y="count",
            color="category",
            barmode="stack",
            labels={
                x_field: x_label,
                "count": y_label,
                "category": "Category",
            },
        )

        fig.update_layout(
            margin=dict(t=40, l=60, r=40, b=60),
            height=600,
            showlegend=self.config.show_legend,
            template=self.config.color_scheme if self.config.color_scheme else None,
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            xaxis={"showgrid": self.config.show_grid},
            yaxis={"showgrid": self.config.show_grid},
        )

        return self._render_container(
            [
                self._create_config_store(),
                self._create_graph_component(figure=fig),
            ]
        )
