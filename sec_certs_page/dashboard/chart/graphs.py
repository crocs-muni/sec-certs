"""Generic chart components for dynamic user-created charts.

These components are used when users create charts from the dashboard UI
by selecting axes and chart types. They use FigureBuilder to create figures
from the chart configuration.
"""

from typing import Any

import pandas as pd
from dash.development.base_component import Component

from ..filters.query_builder import build_chart_pipeline
from .base import BaseChart
from .figure_builder import FigureBuilder


class GenericChartComponent(BaseChart):
    """Base for generic chart components that render from configuration.

    Unlike predefined charts (CCCertsPerYear, etc.) that have hardcoded
    data transformations, generic charts use the Chart configuration's
    x_axis/y_axis/aggregation settings to dynamically create visualizations.

    If a query_pipeline is stored in the chart config, it uses MongoDB
    aggregation for better performance. Otherwise, it fetches raw data
    and uses FigureBuilder to aggregate in pandas.
    """

    def render(self, filter_values: dict[str, Any] | None = None) -> Component:
        """Render the chart using aggregation pipeline or FigureBuilder."""
        merged_filters = self._get_merged_filter_values(filter_values)

        try:
            # Try to use aggregation pipeline for better performance
            df = self._get_aggregated_data(merged_filters)

            if df.empty:
                return self._render_container([self._render_empty_state()])

            # If we used aggregation pipeline, data is already aggregated
            # Create figure directly from the aggregated data
            if self.config.query_pipeline:
                fig = FigureBuilder.create_figure_from_aggregated(self.config, df)
            else:
                # Fallback to FigureBuilder with raw data
                fig = FigureBuilder.create_figure(self.config, df)

            return self._render_container(
                [
                    self._create_config_store(),
                    self._create_graph_component(figure=fig),
                ]
            )
        except Exception as e:
            return self._render_container([self._render_error_state(f"Error creating chart: {str(e)}")])

    def _get_aggregated_data(self, filter_values: dict[str, Any] | None) -> pd.DataFrame:
        """Get data using aggregation pipeline if available, otherwise raw data.

        :param filter_values: Optional filter values to apply
        :return: DataFrame with data (aggregated or raw depending on pipeline)
        """
        if self.config.query_pipeline is not None:
            pipeline = build_chart_pipeline(self.config, filter_values)
            return self.data_service.execute_aggregation_pipeline(
                collection_name=self.config.collection_name,
                pipeline=pipeline,
            )
        return self.data_service.get_dataframe(
            collection_name=self.config.collection_name,
            filter_values=filter_values,
        )


class BarChartComponent(GenericChartComponent):
    """Bar chart implementation."""

    @property
    def title(self) -> str:
        return self.config.title if self.config else "Bar Chart"


class LineChartComponent(GenericChartComponent):
    """Line chart implementation."""

    @property
    def title(self) -> str:
        return self.config.title if self.config else "Line Chart"


class PieChartComponent(GenericChartComponent):
    """Pie chart implementation."""

    @property
    def title(self) -> str:
        return self.config.title if self.config else "Pie Chart"


class ScatterChartComponent(GenericChartComponent):
    """Scatter chart implementation."""

    @property
    def title(self) -> str:
        return self.config.title if self.config else "Scatter Chart"


class BoxChartComponent(GenericChartComponent):
    """Box chart implementation."""

    @property
    def title(self) -> str:
        return self.config.title if self.config else "Box Chart"


class HistogramChartComponent(GenericChartComponent):
    """Histogram chart implementation."""

    @property
    def title(self) -> str:
        return self.config.title if self.config else "Histogram"
