from dash import dcc, html
from dash.development.base_component import Component

from sec_certs_page.dashboard.chart.base import BaseChart


class BarChartComponent(BaseChart):
    """Bar chart implementation."""

    @property
    def title(self) -> str:
        return self.config.title if self.config else "Bar Chart"

    def render(self) -> Component:
        return self._render_container(
            [
                *self._render_header(),
                self._create_graph_component(),
                self._create_config_store(),
            ]
        )


class LineChartComponent(BaseChart):
    """Line chart implementation."""

    @property
    def title(self) -> str:
        return self.config.title if self.config else "Line Chart"

    def render(self) -> Component:
        return self._render_container(
            [
                *self._render_header(),
                self._create_graph_component(),
                self._create_config_store(),
            ]
        )


class PieChartComponent(BaseChart):
    """Pie chart implementation."""

    @property
    def title(self) -> str:
        return self.config.title if self.config else "Pie Chart"

    def render(self) -> Component:
        return self._render_container(
            [
                *self._render_header(),
                self._create_graph_component(),
                self._create_config_store(),
            ]
        )


class ScatterChartComponent(BaseChart):
    """Scatter chart implementation."""

    @property
    def title(self) -> str:
        return self.config.title if self.config else "Scatter Chart"

    def render(self) -> Component:
        return self._render_container(
            [
                *self._render_header(),
                self._create_graph_component(),
                self._create_config_store(),
            ]
        )


class BoxChartComponent(BaseChart):
    """Box chart implementation."""

    @property
    def title(self) -> str:
        return self.config.title if self.config else "Box Chart"

    def render(self) -> Component:
        return self._render_container(
            [
                *self._render_header(),
                self._create_graph_component(),
                self._create_config_store(),
            ]
        )


class HistogramChartComponent(BaseChart):
    """Histogram chart implementation."""

    @property
    def title(self) -> str:
        return self.config.title if self.config else "Histogram"

    def render(self) -> Component:
        return self._render_container(
            [
                *self._render_header(),
                self._create_graph_component(),
                self._create_config_store(),
            ]
        )
