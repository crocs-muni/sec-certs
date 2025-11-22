from typing import Dict, Iterator

from sec_certs_page.dashboard.types.common import CollectionName

from .base import BaseChart


class ChartRegistry:
    """A registry for storing and managing chart components."""

    def __init__(self, dataset_type: CollectionName) -> None:
        self.dataset_type = dataset_type
        self._charts: Dict[str, BaseChart] = {}

    def register(self, chart: BaseChart) -> None:
        """Register a new chart instance."""
        if chart.id in self._charts:
            raise ValueError(f"Chart with ID '{chart.id}' is already registered.")
        self._charts[chart.id] = chart

    def get(self, chart_id: str) -> BaseChart | None:
        """Get a chart by ID, or None if not found."""
        return self._charts.get(chart_id)

    def __getitem__(self, chart_id: str) -> BaseChart:
        """Retrieve a chart instance by its ID."""
        return self._charts[chart_id]

    def __iter__(self) -> Iterator[BaseChart]:
        """Allows iteration over the registered charts."""
        return iter(self._charts.values())

    def __len__(self) -> int:
        """Return the number of registered charts."""
        return len(self._charts)
