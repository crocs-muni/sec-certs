"""Error chart component for displaying chart creation/rendering failures."""

from typing import Any

from dash.development.base_component import Component

from ..chart.chart import Chart
from ..data import DataService
from .base import BaseChart


class ErrorChart(BaseChart):
    """Chart that displays error messages when chart creation/rendering fails.

    Inherits from BaseChart and doesn't use data_service (ignores parameter).
    """

    def __init__(
        self,
        graph_id: str,
        error_message: str,
        title: str = "Error Loading Chart",
        config: Chart | None = None,
    ) -> None:
        super().__init__(
            graph_id=graph_id,
            chart_type="bar",  # Doesn't matter for error display
            config=config,  # type: ignore  # config can be None for error charts
        )
        self.error_message = error_message
        self._title = title

    @property
    def title(self) -> str:
        """Return the chart title."""
        return self._title

    def render(self, data_service: DataService | None = None, filter_values: dict[str, Any] | None = None) -> Component:
        """Render an error state with the error message."""
        return self._render_container([self._render_error_state(f"Failed to create chart: {self.error_message}")])
