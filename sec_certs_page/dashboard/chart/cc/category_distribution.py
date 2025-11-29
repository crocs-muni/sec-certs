from typing import Any

import plotly.graph_objects as go
from dash import html
from dash.development.base_component import Component

from ...chart.chart import Chart
from ...data import DataService
from ..base import BaseChart


class CCCategoryDistribution(BaseChart):
    """A pie chart showing the distribution of CC certificate categories."""

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

    def render(self, filter_values: dict[str, Any] | None = None) -> Component:
        """Render the pie chart showing category distribution."""
        merged_filters = self._get_merged_filter_values(filter_values)

        df = self.data_service.get_cc_dataframe(filter_values=merged_filters if merged_filters else None)

        if df.empty:
            return self._render_container([self._render_empty_state()])

        category_counts = df["category"].value_counts()

        fig = go.Figure(
            go.Pie(
                labels=category_counts.index,
                values=category_counts.values,
                hole=0.3,
                textposition="inside",
                textinfo="percent+label",
            )
        )

        fig.update_layout(
            margin={"t": 40, "l": 40, "r": 40, "b": 40},
            height=450,
            showlegend=self.config.show_legend if self.config else True,
        )

        return self._render_container(
            [
                self._create_config_store(),
                self._create_graph_component(figure=fig),
            ]
        )
