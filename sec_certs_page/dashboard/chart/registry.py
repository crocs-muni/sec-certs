from typing import Dict, Iterator

from ..types.common import CollectionName
from .base import BaseChart


class ChartRegistry:
    """A registry for storing predefined chart components.

    This registry stores immutable, built-in charts that populate dropdowns.
    Custom/user-created charts are NOT stored here - they are created on-demand
    from the chart_configs store (dcc.Store) which lives in the client browser.

    - Predefined charts are registered once at startup (same across all workers)
    - Custom charts are created fresh on each request from client-side config
    - No mutable server-side state that could desync between workers
    """

    def __init__(self, collection_name: CollectionName) -> None:
        self.collection_name = collection_name
        self._predefined_charts: Dict[str, BaseChart] = {}

    def register(self, chart: BaseChart) -> None:
        """Register a new predefined chart instance."""
        if chart.id in self._predefined_charts:
            raise ValueError(f"Chart with ID '{chart.id}' is already registered.")
        self._predefined_charts[chart.id] = chart

    def get_predefined(self, chart_id: str) -> BaseChart | None:
        """Get a predefined chart by ID."""
        return self._predefined_charts.get(chart_id)

    def __getitem__(self, chart_id: str) -> BaseChart:
        """Retrieve a predefined chart instance by its ID."""
        chart = self._predefined_charts.get(chart_id)
        if chart is None:
            raise KeyError(f"Predefined chart '{chart_id}' not found")
        return chart

    def __iter__(self) -> Iterator[BaseChart]:
        """Iterate over predefined charts (for dropdown population)."""
        return iter(self._predefined_charts.values())

    def __len__(self) -> int:
        """Return the number of predefined charts."""
        return len(self._predefined_charts)
