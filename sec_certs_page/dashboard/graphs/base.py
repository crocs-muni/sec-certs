"""Defines the base components for graph creation and registration."""

from abc import ABC, abstractmethod
from typing import Protocol

import plotly.express as px
from dash import Dash
from dash.development.base_component import Component

from sec_certs_page.dashboard.data import DataService


class SupportsRegisterCallbacks(Protocol):
    """Protocol for defining the `register_callbacks` method signature."""

    def register_callbacks(self, app: Dash) -> None: ...


class BaseGraph(ABC):
    """
    Abstract base class for all graph components in the dashboard.

    This class defines the common interface for graphs, ensuring they can be
    registered and rendered dynamically. It follows the Strategy Pattern, where

    each concrete graph class is a different strategy for visualizing data.
    """

    def __init__(self, graph_id: str, data_service: DataService):
        """
        Args:
            graph_id: A unique identifier for the graph component.
            data_service: The service to fetch data for the graph.
        """
        self.graph_id = graph_id
        self.data_service = data_service
        self.color_palette = px.colors.qualitative.T10

    @property
    def id(self) -> str:
        """The unique identifier for the Dash component."""
        return self.graph_id

    @property
    @abstractmethod
    def title(self) -> str:
        """The user-friendly title of the graph."""
        raise NotImplementedError

    @abstractmethod
    def render(self) -> Component:
        """
        Renders the graph component.

        Returns:
            The Dash component (e.g., dcc.Graph) to be displayed.
        """
        raise NotImplementedError

    @abstractmethod
    def register_callback(self, app: Dash) -> None:
        """
        Registers the necessary callbacks for the graph.

        Each graph is responsible for its own update logic.

        Args:
            app: The main Dash application instance.
        """
        raise NotImplementedError
