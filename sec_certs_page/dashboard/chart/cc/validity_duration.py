from typing import Any

import pandas as pd
import plotly.express as px
from dash.development.base_component import Component

from ...chart.chart import ChartConfig
from ...data import DataService
from ..base import BaseChart


class CCValidityDuration(BaseChart):
    """A box plot showing the variance of certificate validity duration per year."""

    def __init__(self, config: ChartConfig) -> None:
        super().__init__(config=config)

    @property
    def title(self) -> str:
        return self.config.title if self.config and self.config.title else "Certificate Validity Duration"

    def render(self, data_service: DataService | None = None, filter_values: dict[str, Any] | None = None) -> Component:
        """Render the box plot showing certificate validity duration variance."""
        if not data_service:
            return self._render_container([self._render_error_state("Data service not provided")])

        merged_filters = self._get_merged_filter_values(filter_values)

        df = data_service.get_cc_dataframe(filter_values=merged_filters if merged_filters else None)

        if df.empty:
            return self._render_container([self._render_empty_state()])

        # Convert date columns and calculate validity
        df["not_valid_before"] = pd.to_datetime(df["not_valid_before"], unit="ms", errors="coerce")
        df["not_valid_after"] = pd.to_datetime(df["not_valid_after"], unit="ms", errors="coerce")
        df = df.dropna(subset=["not_valid_before", "not_valid_after"])

        # Calculate validity duration using config y_axis field
        y_field = self.config.y_axis.field if self.config.y_axis else "validity_days"
        df[y_field] = (df["not_valid_after"] - df["not_valid_before"]).dt.days
        df = df[df[y_field] >= 0]

        if df.empty:
            return self._render_container([self._render_empty_state("No valid date ranges found")])

        # Use config x_axis field for grouping
        x_field = self.config.x_axis.field
        df[x_field] = df["not_valid_before"].dt.year
        sorted_years = sorted(df[x_field].unique())

        x_label = self.config.x_axis.label
        y_label = self.config.y_axis.label if self.config.y_axis else "Validity Duration (days)"

        fig = px.box(
            df,
            x=x_field,
            y=y_field,
            labels={
                y_field: y_label,
                x_field: x_label,
            },
            category_orders={x_field: sorted_years},
        )

        fig.update_layout(
            height=600,
            margin=dict(t=40, l=60, r=40, b=60),
            showlegend=self.config.show_legend,
            template=self.config.color_scheme if self.config.color_scheme else None,
            xaxis={"showgrid": self.config.show_grid},
            yaxis={"showgrid": self.config.show_grid},
        )

        return self._render_container(
            [
                self._create_config_store(),
                self._create_graph_component(figure=fig),
            ]
        )
