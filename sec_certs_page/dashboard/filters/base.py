"""Defines the base components for filter creation."""

from abc import ABC, abstractmethod

from dash.development.base_component import Component


class BaseFilter(ABC):
    """Abstract base class for all filter components in the dashboard."""

    def __init__(self, filter_id: str):
        """
        :param filter_id: A unique identifier for the filter component.
        :type filter_id: str
        """
        self.filter_id = filter_id

    @property
    def id(self) -> str:
        """The unique identifier for the Dash component."""
        return self.filter_id

    @abstractmethod
    def render(self, dataset_type: str = "cc") -> Component:
        """
        Renders the filter's UI component (e.g., dcc.Dropdown).

        :param dataset_type: The type of dataset ('cc' or 'fips') for lazy loading
        :return: The Dash component to be displayed.
        :rtype: Component
        """
        raise NotImplementedError
