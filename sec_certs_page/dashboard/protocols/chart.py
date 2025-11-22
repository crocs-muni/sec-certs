import uuid

from dash.development.base_component import Component

from sec_certs_page.dashboard.types.chart import ChartConfig


class ChartProtocol:
    """Protocol for chart classes."""

    id_: uuid.UUID
    title: str
    type_: str
    order: int
    """Numeric order for sorting charts in the dashboard."""
    config: ChartConfig
    query_pipeline: list[dict]
    """Defines the process to query data from database to create the chart."""

    def to_json(self) -> dict:
        """
        Serializes the Chart instance to a JSON-compatible dictionary.

        :return: A dictionary representation of the Chart.
        """
        ...

    def from_json(self, data: dict) -> "ChartProtocol":
        """
        Deserializes a Chart instance from a JSON-compatible dictionary.

        :param data: A dictionary representation of the Chart.
        """
        ...

    def render(self) -> Component:
        """
        Renders the chart component.

        :return: The Dash component (e.g., dcc.Graph) to be displayed.
        :rtype: Component
        """
        ...

    def layout(self) -> Component:
        """
        Renders the layout component for the chart.

        :return: The Dash layout component (e.g., html.Div) to be displayed.
        :rtype: Component
        """
        ...
