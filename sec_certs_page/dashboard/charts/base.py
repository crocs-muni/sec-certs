from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Literal, Optional, Protocol

import plotly.express as px
from dash import Dash, dcc, html
from dash.development.base_component import Component

from ..data import DataService


class SupportsRegisterCallbacks(Protocol):
    """Protocol for defining the `register_callbacks` method signature."""

    def register_callbacks(self, app: Dash) -> None: ...


@dataclass
class BaseChart(ABC):
    """
    Abstract base class for all chart components in the dashboard.

    This class defines the common interface for charts, ensuring they can be
    registered and rendered dynamically. It follows the Strategy Pattern, where
    each concrete chart class is a different strategy for visualizing data.
    """

    graph_id: str
    data_service: DataService
    chart_type: Literal["pie", "bar", "box", "line", "scatter"]

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

        :return: The Dash component (e.g., dcc.Graph) to be displayed.
        :rtype: Component
        """
        raise NotImplementedError

    @abstractmethod
    def register_callback(self, app: Dash) -> None:
        """
        Registers the necessary callbacks for the graph.

        Each graph is responsible for its own update logic.

        :param app: The main Dash application instance.
        :type app: Dash
        """
        raise NotImplementedError
