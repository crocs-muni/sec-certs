from typing import Dict, Iterator

from ..types.common import CollectionName
from .base import BaseChart


class ChartRegistry:
    """A registry for storing and managing chart components.

    This registry has two layers:
    - Predefined charts: Immutable, built-in charts that populate dropdowns
    - Active charts: All charts currently being rendered (predefined + custom)
    """

    def __init__(self, collection_name: CollectionName) -> None:
        self.collection_name = collection_name
        self._predefined_charts: Dict[str, BaseChart] = {}
        self._active_charts: Dict[str, BaseChart] = {}

    def register(self, chart: BaseChart) -> None:
        """Register a new predefined chart instance."""
        if chart.id in self._predefined_charts:
            raise ValueError(f"Chart with ID '{chart.id}' is already registered.")
        self._predefined_charts[chart.id] = chart

    def register_active(self, chart: BaseChart) -> None:
        """Register or update a chart in the active registry (for rendering)."""
        self._active_charts[chart.id] = chart

    def unregister_active(self, chart_id: str) -> None:
        """Remove a chart from the active registry.

        :param chart_id: The ID of the chart to unregister
        """
        if chart_id in self._active_charts:
            del self._active_charts[chart_id]

    def clear_active(self) -> None:
        """Clear all active charts (but keep predefined ones)."""
        self._active_charts.clear()

    def get(self, chart_id: str) -> BaseChart | None:
        """Get a chart by ID from active charts first, then predefined."""
        return self._active_charts.get(chart_id) or self._predefined_charts.get(chart_id)

    def get_predefined(self, chart_id: str) -> BaseChart | None:
        """Get a predefined chart by ID."""
        return self._predefined_charts.get(chart_id)

    def __getitem__(self, chart_id: str) -> BaseChart:
        """Retrieve a chart instance by its ID (checks both registries)."""
        chart = self.get(chart_id)
        if chart is None:
            raise KeyError(f"Chart '{chart_id}' not found")
        return chart

    def __iter__(self) -> Iterator[BaseChart]:
        """Iterate over predefined charts only (for dropdown population)."""
        return iter(self._predefined_charts.values())

    def __len__(self) -> int:
        """Return the number of predefined charts."""
        return len(self._predefined_charts)
