"""Generic chart components for dynamic user-created charts.

These components are used when users create charts from the dashboard UI
by selecting axes and chart types. They use FigureBuilder to create figures
from the chart configuration.
"""

from typing import Any

from dash.development.base_component import Component

from .base import BaseChart
from .figure_builder import FigureBuilder


class GenericChartComponent(BaseChart):
    """Base for generic chart components that render from configuration.

    Unlike predefined charts (CCCertsPerYear, etc.) that have hardcoded
    data transformations, generic charts use the Chart configuration's
    x_axis/y_axis/aggregation settings to dynamically create visualizations.
    """

    def render(self, filter_values: dict[str, Any] | None = None) -> Component:
        """Render the chart using FigureBuilder."""
        merged_filters = self._get_merged_filter_values(filter_values)

        # Get data for the collection type specified in the chart config
        df = self.data_service.get_dataframe(
            collection_type=self.config.collection_type,
            filter_values=merged_filters if merged_filters else None,
        )

        if df.empty:
            return self._render_container([self._render_empty_state()])

        try:
            fig = FigureBuilder.create_figure(self.config, df)
            return self._render_container(
                [
                    self._create_config_store(),
                    self._create_graph_component(figure=fig),
                ]
            )
        except Exception as e:
            return self._render_container([self._render_error_state(f"Error creating chart: {str(e)}")])


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
