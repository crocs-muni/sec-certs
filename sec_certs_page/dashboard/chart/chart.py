"""Generic chart components for dynamic user-created charts.

These components are used when users create charts from the dashboard UI
by selecting axes and chart types. They use FigureBuilder to create figures
from the chart configuration.
"""

import logging
from typing import Any

import pandas as pd
from dash.development.base_component import Component

from ..data import DataService
from ..filters.query_builder import build_chart_pipeline
from ..types.chart import ChartType
from .base import BaseChart
from .figure_builder import FigureBuilder

logger = logging.getLogger(__name__)


class ConfigurableChart(BaseChart):
    """Base for generic chart components that render from configuration.

    Generic charts use the Chart configuration's x_axis/y_axis/aggregation
    settings to dynamically create visualizations.

    If a query_pipeline is stored in the chart config, it uses MongoDB
    aggregation for better performance. Otherwise, it fetches raw data
    and uses FigureBuilder to aggregate in pandas.
    """

    def render(self, data_service: DataService | None = None, filter_values: dict[str, Any] | None = None) -> Component:
        """Render the chart using aggregation pipeline or FigureBuilder."""
        if not data_service:
            return self._render_container([self._render_error_state("Data service not provided")])

        merged_filters = self._get_merged_filter_values(filter_values)

        try:
            # Get data - will use aggregation pipeline when possible
            df = self._get_aggregated_data(data_service, merged_filters)

            if df.empty:
                return self._render_container([self._render_empty_state()])

            if self.config.chart_type in (ChartType.BOX, ChartType.HISTOGRAM):
                fig = FigureBuilder.create_figure(self.config, df)
            else:
                # Check if data is already aggregated by examining columns
                # Aggregated data has flattened field names (dots replaced with underscores)
                x_field_flat = self.config.x_axis.field.replace(".", "_")
                is_aggregated = x_field_flat in df.columns

                if is_aggregated:
                    fig = FigureBuilder.create_figure_from_aggregated(self.config, df)
                else:
                    # Raw data - FigureBuilder will aggregate it
                    fig = FigureBuilder.create_figure(self.config, df)

            return self._render_container(
                [
                    self._create_config_store(),
                    self._create_graph_component(figure=fig),
                ]
            )
        except Exception as e:
            error_message = f"[RENDER] {self.config.title} error creating chart"
            logger.exception(error_message)
            return self._render_container([self._render_error_state(f"Error creating chart: {str(e)}")])

    def _get_aggregated_data(self, data_service: DataService, filter_values: dict[str, Any] | None) -> pd.DataFrame:
        """Get data using aggregation pipeline if available, otherwise raw data.

        :param data_service: Data service to fetch data from
        :param filter_values: Optional filter values to apply
        :return: DataFrame with data (aggregated or raw depending on what succeeded)
        """
        # Always try to use aggregation pipeline for performance
        # The pipeline is rebuilt from config even if query_pipeline is None (security)
        try:
            pipeline = build_chart_pipeline(self.config, filter_values)
            return data_service.execute_aggregation_pipeline(
                collection_name=self.config.collection_name,
                pipeline=pipeline,
            )
        except Exception:
            logger.exception(
                f"[DATA] Failed to use aggregation pipeline for {self.config.title}, falling back to raw data"
            )
            return data_service.get_dataframe(
                collection_name=self.config.collection_name,
                filter_values=filter_values,
            )


class BarChartComponent(ConfigurableChart):
    """Bar chart implementation."""

    @property
    def title(self) -> str:
        return self.config.title if self.config else "Bar Chart"


class LineChartComponent(ConfigurableChart):
    """Line chart implementation."""

    @property
    def title(self) -> str:
        return self.config.title if self.config else "Line Chart"


class PieChartComponent(ConfigurableChart):
    """Pie chart implementation."""

    @property
    def title(self) -> str:
        return self.config.title if self.config else "Pie Chart"


class ScatterChartComponent(ConfigurableChart):
    """Scatter chart implementation."""

    @property
    def title(self) -> str:
        return self.config.title if self.config else "Scatter Chart"


class BoxChartComponent(ConfigurableChart):
    """Box chart implementation."""

    @property
    def title(self) -> str:
        return self.config.title if self.config else "Box Chart"


class HistogramChartComponent(ConfigurableChart):
    """Histogram chart implementation."""

    @property
    def title(self) -> str:
        return self.config.title if self.config else "Histogram"
