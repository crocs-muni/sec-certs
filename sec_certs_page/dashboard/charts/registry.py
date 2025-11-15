"""Implements the Registry Pattern for managing dashboard graphs."""

from typing import Dict, Iterator

from .base import BaseChart


class ChartRegistry:
    """A registry for storing and managing chart components.

    This class follows the Singleton and Registry design patterns to provide a
    central point of access for all chart instances within the application.
    """

    def __init__(self) -> None:
        self._charts: Dict[str, BaseChart] = {}

    def register(self, chart: BaseChart) -> None:
        """Registers a new chart instance.

        :param chart: An instance of a class derived from BaseChart.
        :type chart: BaseChart

        :raises ValueError: If a chart with the same ID is already registered.
        """
        if chart.id in self._charts:
            raise ValueError(f"Chart with ID '{chart.id}' is already registered.")
        self._charts[chart.id] = chart

    def __getitem__(self, chart_id: str) -> BaseChart:
        """Retrieves a chart instance by its ID.

        :param chart_id: The unique identifier of the chart.
        :type chart_id: str

        :return: The chart instance.
        :rtype: BaseChart
        """
        return self._charts[chart_id]

    def __iter__(self) -> Iterator[BaseChart]:
        """Allows iteration over the registered charts."""
        return iter(self._charts.values())
