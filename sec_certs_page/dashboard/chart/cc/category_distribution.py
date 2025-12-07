from typing import Any

import plotly.express as px
from dash.development.base_component import Component

from ...chart.chart import ChartConfig
from ...data import DataService
from ..base import BaseChart


class CCCategoryDistribution(BaseChart):
    """A pie chart showing the distribution of CC certificate categories."""

    def __init__(self, config: ChartConfig) -> None:
        super().__init__(config=config)

    @property
    def title(self) -> str:
        return self.config.title if self.config and self.config.title else "Category Distribution"

    def render(self, data_service: DataService | None = None, filter_values: dict[str, Any] | None = None) -> Component:
        """Render the pie chart showing category distribution."""
        if not data_service:
            return self._render_container([self._render_error_state("Data service not provided")])

        merged_filters = self._get_merged_filter_values(filter_values)

        df = data_service.get_cc_dataframe(filter_values=merged_filters if merged_filters else None)

        if df.empty:
            return self._render_container([self._render_empty_state()])

        category_counts = df["category"].value_counts().reset_index()
        category_counts.columns = ["category", "count"]

        x_label = self.config.x_axis.label if self.config.x_axis else "Category"
        y_label = self.config.y_axis.label if self.config.y_axis else "Count"

        fig = px.pie(
            category_counts,
            names="category",
            values="count",
            hole=0.3,
            labels={"category": x_label, "count": y_label},
        )

        fig.update_traces(textposition="inside", textinfo="percent+label")

        fig.update_layout(
            margin={"t": 40, "l": 40, "r": 40, "b": 40},
            height=600,
            showlegend=self.config.show_legend,
            template=self.config.color_scheme if self.config.color_scheme else None,
        )

        return self._render_container(
            [
                self._create_config_store(),
                self._create_graph_component(figure=fig),
            ]
        )
