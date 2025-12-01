from typing import Any

import pandas as pd
import plotly.express as px
from dash.development.base_component import Component

from ...chart.chart import Chart
from ...data import DataService
from ..base import BaseChart


class CCValidityDuration(BaseChart):
    """A box plot showing the variance of certificate validity duration per year."""

    def __init__(self, graph_id: str, data_service: DataService, config: Chart) -> None:
        super().__init__(graph_id, data_service, chart_type="box", config=config)

    @property
    def title(self) -> str:
        return self.config.title if self.config and self.config.title else "Certificate Validity Duration"

    def render(self, filter_values: dict[str, Any] | None = None) -> Component:
        """Render the box plot showing certificate validity duration variance."""
        merged_filters = self._get_merged_filter_values(filter_values)

        df = self.data_service.get_cc_dataframe(filter_values=merged_filters if merged_filters else None)

        if df.empty:
            return self._render_container([self._render_empty_state()])

        # Convert date columns and calculate validity
        df["not_valid_before"] = pd.to_datetime(df["not_valid_before"], unit="ms", errors="coerce")
        df["not_valid_after"] = pd.to_datetime(df["not_valid_after"], unit="ms", errors="coerce")
        df = df.dropna(subset=["not_valid_before", "not_valid_after"])

        df["validity_days"] = (df["not_valid_after"] - df["not_valid_before"]).dt.days
        df = df[df["validity_days"] >= 0]

        if df.empty:
            return self._render_container([self._render_empty_state("No valid date ranges found")])

        df["year_from"] = df["not_valid_before"].dt.year
        sorted_years = sorted(df["year_from"].unique())

        x_label = self.config.x_axis.label if self.config and self.config.x_axis else "Year of Certification"
        y_label = self.config.y_axis.label if self.config and self.config.y_axis else "Validity Duration (days)"

        fig = px.box(
            df,
            x="year_from",
            y="validity_days",
            labels={
                "validity_days": y_label,
                "year_from": x_label,
            },
            category_orders={"year_from": sorted_years},
        )

        fig.update_layout(
            height=600,
            margin=dict(t=40, l=60, r=40, b=60),
            showlegend=self.config.show_legend if self.config else False,
            colorway=self.config.color_scheme if self.config and self.config.color_scheme else None,
        )

        return self._render_container(
            [
                self._create_config_store(),
                self._create_graph_component(figure=fig),
            ]
        )
