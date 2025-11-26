from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal, Protocol

from dash import Dash, dcc, html
from dash.development.base_component import Component

from ..chart.chart import Chart
from ..data import DataService


class SupportsRegisterCallbacks(Protocol):
    """Protocol for defining the register_callbacks method signature."""

    def register_callbacks(self, app: Dash) -> None: ...


@dataclass
class BaseChart(ABC):
    """Abstract base for runtime chart components."""

    graph_id: str
    data_service: DataService
    chart_type: Literal["pie", "bar", "box", "line", "scatter", "histogram"]
    config: Chart

    @property
    def id(self) -> str:
        return self.graph_id

    @property
    @abstractmethod
    def title(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def render(self) -> Component:
        """Render the Dash component."""
        raise NotImplementedError

    def _render_header(self) -> list[Component]:
        """Common header with title and refresh button."""
        return [
            html.Div(
                style={
                    "display": "flex",
                    "justifyContent": "space-between",
                    "alignItems": "center",
                    "marginBottom": "10px",
                },
                children=[
                    html.H4(self.title, style={"margin": "0"}),
                    html.Button(
                        "🔄 Refresh",
                        id={"type": "chart-refresh", "index": self.graph_id},
                        n_clicks=0,
                        style={"padding": "5px 15px"},
                    ),
                ],
            )
        ]

    def _render_container(self, children: list[Component]) -> html.Div:
        """Wrap children in a styled container."""
        return html.Div(
            id={"type": "chart-container", "index": self.graph_id},
            style={
                "border": "1px solid #ddd",
                "borderRadius": "8px",
                "padding": "15px",
                "marginBottom": "20px",
            },
            children=children,
        )

    def _create_graph_component(self) -> dcc.Graph:
        """Create the graph component with pattern-matching ID."""
        return dcc.Graph(
            id={"type": "chart-graph", "index": self.graph_id},
            config={
                "displayModeBar": True,
                "toImageButtonOptions": {
                    "format": "svg",
                    "filename": f"chart_{self.graph_id}",
                },
            },
        )

    def _create_config_store(self) -> dcc.Store:
        """Create store for chart configuration."""
        return dcc.Store(
            id={"type": "chart-config", "index": self.graph_id},
            data=self.config.to_dict(),
        )
