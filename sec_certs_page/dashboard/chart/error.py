"""Error chart component for displaying chart creation/rendering failures."""

import logging
from typing import TYPE_CHECKING, Any, Optional

from dash.development.base_component import Component

from .config import ChartConfig
from .base import BaseChart

if TYPE_CHECKING:
    from ..data import DataService


logger = logging.getLogger(__name__)


class ErrorChart(BaseChart):
    """Chart that displays error messages when chart creation/rendering fails.

    Inherits from BaseChart and doesn't use data_service (ignores parameter).
    Preserves the original chart's configuration to maintain ID and display properties.
    """

    def __init__(
        self,
        config: ChartConfig,
        error_message: str,
        title: str | None = None,
    ) -> None:
        super().__init__(
            config=config,
        )
        self.error_message = error_message
        self._title = title or config.title

    @property
    def title(self) -> str:
        """Return the chart title."""
        return self._title

    def render(
        self, data_service: Optional["DataService"] = None, filter_values: dict[str, Any] | None = None
    ) -> Component:
        """Render an error state with the error message."""
        error_message = f"ErrorChart [{self.config.name}]: {self.error_message}"
        logger.error(error_message)
        return self._render_container([self._render_error_state(f"Failed to create chart: {self.error_message}")])
