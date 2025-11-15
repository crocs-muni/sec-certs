from abc import ABC, abstractmethod
from typing import Literal, Optional, Protocol

import plotly.express as px
from dash import Dash, dcc, html
from dash.development.base_component import Component

from ..data import DataService


class SupportsRegisterCallbacks(Protocol):
    """Protocol for defining the `register_callbacks` method signature."""

    def register_callbacks(self, app: Dash) -> None: ...


class BaseChart(ABC):
    """
    Abstract base class for all graph components in the dashboard.

    This class defines the common interface for graphs, ensuring they can be
    registered and rendered dynamically. It follows the Strategy Pattern, where
    each concrete graph class is a different strategy for visualizing data.
    """

    def __init__(
        self,
        graph_id: str,
        data_service: DataService,
        chart_type: Literal["pie", "bar", "box", "line", "scatter"] = "pie",
        available_chart_types: list[str] | None = None,
    ):
        """
        :param graph_id: A unique identifier for the graph component.
        :type graph_id: str
        :param data_service: The service to fetch data for the graph.
        :type data_service: DataService
        :param chart_type: The default chart type to display.
        :type chart_type: str
        :param available_chart_types: A list of chart types this graph supports.
        :type available_chart_types: Optional[List[str]]
        """
        self.graph_id = graph_id
        self.data_service = data_service
        self.color_palette = px.colors.qualitative.T10
        self.chart_type = chart_type
        self.available_chart_types = available_chart_types if available_chart_types is not None else []

    @property
    def id(self) -> str:
        """The unique identifier for the Dash component."""
        return self.graph_id

    @property
    def chart_type_selector_id(self) -> str:
        """The unique identifier for the chart type selector dropdown."""
        return f"{self.graph_id}-type-selector"

    def _render_header(self) -> list[Component]:
        """Renders the graph title and a dropdown to switch chart types if multiple are available."""
        header_elements: list[Component] = [html.H2(self.title)]
        if len(self.available_chart_types) > 1:
            header_elements.append(
                dcc.Dropdown(
                    id=self.chart_type_selector_id,
                    options=[
                        {"label": f"{chart.capitalize()} Chart", "value": chart} for chart in self.available_chart_types
                    ],
                    value=self.chart_type,
                    clearable=False,
                    style={"width": "200px", "marginBottom": "10px"},
                )
            )
        return header_elements

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
