import pandas as pd
import plotly.express as px
from dash import dcc, html

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

    def render(self, filter_values: dict | None = None) -> html.Div:
        """Render the box plot with per-chart filter configuration."""
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

        df["not_valid_before"] = pd.to_datetime(df["not_valid_before"], unit="ms", errors="coerce")
        df["not_valid_after"] = pd.to_datetime(df["not_valid_after"], unit="ms", errors="coerce")
        df.dropna(subset=["not_valid_before", "not_valid_after"], inplace=True)

        df["validity_days"] = (df["not_valid_after"] - df["not_valid_before"]).dt.days
        df = df[df["validity_days"] >= 0]

        if df.empty:
            return self._render_container(
                [
                    *self._render_header(),
                    html.P("No data matches filters", style={"color": "gray", "textAlign": "center"}),
                ]
            )

        df["year_from"] = df["not_valid_before"].dt.year
        sorted_years = sorted(df["year_from"].unique())

        x_label = self.config.x_axis.label if self.config and self.config.x_axis else "Year of Certification"
        y_label = (
            self.config.y_axis.label if self.config and self.config.y_axis else "Lifetime of certificates (in days)"
        )

        fig = px.box(
            df,
            x="year_from",
            y="validity_days",
            title=self.title,
            labels={
                "validity_days": y_label,
                "year_from": x_label,
            },
            category_orders={"year_from": sorted_years},
        )
        fig.update_layout(
            height=600,
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
