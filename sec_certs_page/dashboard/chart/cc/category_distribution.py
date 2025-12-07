from typing import Any

import plotly.express as px
from dash.development.base_component import Component

from ...chart.chart import Chart
from ...data import DataService
from ..base import BaseChart


class CCCategoryDistribution(BaseChart):
    """A pie chart showing the distribution of CC certificate categories."""

    def __init__(self, graph_id: str, config: Chart) -> None:
        super().__init__(graph_id, chart_type="pie", config=config)

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

        fig = px.pie(
            category_counts,
            names="category",
            values="count",
            hole=0.3,
            labels={"category": "Category", "count": "Count"},
        )

        fig.update_traces(textposition="inside", textinfo="percent+label")

        fig.update_layout(
            margin={"t": 40, "l": 40, "r": 40, "b": 40},
            height=600,
            showlegend=self.config.show_legend if self.config else True,
        )

        return self._render_container(
            [
                self._create_config_store(),
                self._create_graph_component(figure=fig),
            ]
        )
