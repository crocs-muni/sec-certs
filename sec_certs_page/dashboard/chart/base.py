from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import dash_bootstrap_components as dbc
from dash import dcc, html
from dash.development.base_component import Component

from .config import ChartConfig
from ..data import DataService


@dataclass
class BaseChart(ABC):
    """Abstract base for runtime chart components.

    Provides common rendering utilities and defines the interface for chart implementations.
    Subclasses must implement `title` property and `render` method.

    This base class doesn't include data_service as a field - pass it to render() when needed.
    """

    config: ChartConfig

    @property
    def id(self) -> str:
        """Runtime string ID for Dash components (derived from config.chart_id)."""
        return str(self.config.chart_id)

    @property
    @abstractmethod
    def title(self) -> str:
        """Display title for the chart."""
        raise NotImplementedError

    @abstractmethod
    def render(self, data_service: DataService | None = None, filter_values: dict[str, Any] | None = None) -> Component:
        """Render the Dash component.

        :param data_service: Optional data service for charts that need data access (not needed for error charts)
        :param filter_values: Optional dictionary of dashboard-level filter values to apply
        :return: Rendered Dash component
        """
        raise NotImplementedError

    def _render_empty_state(self, message: str = "No data available") -> dbc.Alert:
        """Render an empty state message when no data is available."""
        return dbc.Alert(
            [
                html.I(className="fas fa-info-circle me-2"),
                message,
            ],
            color="info",
            className="text-center my-4",
        )

    def _render_error_state(self, message: str) -> dbc.Alert:
        """Render an error state message."""
        return dbc.Alert(
            [
                html.I(className="fas fa-exclamation-circle me-2"),
                message,
            ],
            color="danger",
            className="text-center my-4",
        )

    def _render_container(self, children: list[Component]) -> html.Div:
        """Wrap children in a styled container.

        Note: The outer card wrapper with header/controls is handled by the
        callbacks module (_create_chart_wrapper). This container is for the
        internal chart content only.
        """
        return html.Div(
            id={"type": "chart-container", "index": self.id},
            className="chart-content",
            children=children,
        )

    def _create_graph_component(self, figure: Any | None = None) -> dcc.Graph:
        """Create the graph component with pattern-matching ID.

        :param figure: Optional Plotly figure to display
        :return: Dash Graph component
        """
        return dcc.Graph(
            id={"type": "chart-graph", "index": self.id},
            figure=figure,
            config={
                "displayModeBar": True,
                "displaylogo": False,
                "responsive": True,
                "toImageButtonOptions": {
                    "format": "svg",
                    "filename": f"chart_{self.id}",
                },
            },
            style={"height": "100%"},
            className="w-100",
        )

    def _create_config_store(self) -> dcc.Store:
        """Create store for chart configuration."""
        return dcc.Store(
            id={"type": "chart-config", "index": self.id},
            data=self.config.to_dict(),
        )

    def _get_merged_filter_values(self, dashboard_filters: dict[str, Any] | None = None) -> dict[str, Any]:
        """Merge chart-level filters with dashboard-level filters.

        Chart-level filters take precedence over dashboard-level filters.

        :param dashboard_filters: Filter values from the dashboard
        :return: Merged filter values dictionary
        """
        # Start with dashboard-level filters
        merged = dict(dashboard_filters) if dashboard_filters else {}

        # Add chart-level filters (these override dashboard filters)
        if self.config:
            if self.config.filter_values:
                merged.update(self.config.filter_values)

            active_filters = self.config.get_active_filters()
            for filter_id, filter_spec in active_filters.items():
                if filter_spec.data is not None:
                    merged[filter_id] = filter_spec.data

        return merged
