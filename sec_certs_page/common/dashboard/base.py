# sec_certs_page/common/dashboard/base.py
from abc import ABC, abstractmethod
from typing import Any, Dict, Generic, TypeVar

import plotly.graph_objects as go
from dash import dcc, html
from dash.development.base_component import Component

from .types import BaseDashboardConfig, ChartConfig

T_Config = TypeVar("T_Config", bound=BaseDashboardConfig)


class BaseChart(ABC):
    """Base class for all charts."""

    def __init__(self, config: ChartConfig):
        """
        Initialize chart with configuration.

        Args:
            config: Chart configuration dictionary
        """
        self.id = config["id"]
        self.title = config["title"]
        self.config = config
        self.figure: go.Figure | None = None

    @abstractmethod
    def get_layout(self) -> Component:
        """Get the Dash layout for this chart."""
        pass

    @abstractmethod
    def update(self, data: Dict[str, Any]) -> None:
        """Update chart with new data."""
        pass


class BaseDashboard(Generic[T_Config]):
    """Base class for all dashboards."""

    def __init__(self, config: T_Config):
        """
        Initialize dashboard with configuration.

        Args:
            config: Dashboard configuration
        """
        self.id = config["id"]
        self.title = config["title"]
        self.refresh_interval = config["refresh_interval"]
        self.config = config
        self.charts: Dict[str, BaseChart] = {}
        self._initialize_charts()

    def _initialize_charts(self) -> None:
        """Initialize charts based on configuration."""
        for chart_config in self.config["charts"]:
            chart = self.create_chart(chart_config)
            if chart:
                self.charts[chart.id] = chart

    @abstractmethod
    def create_chart(self, config: ChartConfig) -> BaseChart | None:
        """Create a chart instance from configuration."""
        pass

    def add_chart(self, config: ChartConfig) -> None:
        """Add a new chart to the dashboard."""
        chart = self.create_chart(config)
        if chart:
            self.charts[chart.id] = chart

    def remove_chart(self, chart_id: str) -> None:
        """Remove a chart from the dashboard."""
        self.charts.pop(chart_id, None)

    def get_layout(self) -> Component:
        """Get the Dash layout for this dashboard."""
        return html.Div([html.H1(self.title), html.Div([chart.get_layout() for chart in self.charts.values()])])

    @abstractmethod
    def register_callbacks(self, app) -> None:
        """Register Dash callbacks for this dashboard."""
        pass
