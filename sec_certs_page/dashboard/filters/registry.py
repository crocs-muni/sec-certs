"""Implements the Registry Pattern for managing dashboard filters."""

from typing import Dict, Iterator

from .base import BaseFilter


class FilterRegistry:

    def __init__(self) -> None:
        self._filters: Dict[str, BaseFilter] = {}

    def register(self, filter_instance: BaseFilter) -> None:
        """
        Registers a new filter instance.

        :param filter_instance: An instance of a class derived from BaseFilter.
        :type filter_instance: BaseFilter

        :raises ValueError: If a filter with the same ID is already registered.
        """
        if filter_instance.id in self._filters:
            raise ValueError(f"Filter with ID '{filter_instance.id}' is already registered.")
        self._filters[filter_instance.id] = filter_instance

    def __getitem__(self, filter_id: str) -> BaseFilter:
        """
        Retrieves a filter instance by its ID.

        :param filter_id: The unique identifier of the filter.
        :type filter_id: str

        :return: The filter instance.
        :rtype: BaseFilter
        """
        return self._filters[filter_id]

    def __iter__(self) -> Iterator[BaseFilter]:
        """Allows iteration over the registered filters."""
        return iter(self._filters.values())

    def clear(self) -> None:
        """Removes all registered filters."""
        self._filters.clear()

    def __len__(self) -> int:
        """Returns the number of registered filters."""
        return len(self._filters)

    def __bool__(self) -> bool:
        """Returns True if registry has filters, False otherwise."""
        return bool(self._filters)
