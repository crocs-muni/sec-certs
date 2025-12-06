import uuid

from dash.development.base_component import Component

from ..types.common import CollectionType


class DashboardProtocol:
    """Protocol for chart classes."""

    dashboard_id: uuid.UUID
    user_id: str
    collection_name: CollectionType
    name: str
    description: str | None
    charts: list[dict] | None
    layout_config: dict | None
    is_default: bool
    created_at: str
    updated_at: str
    """Numeric order for sorting charts in the dashboard."""

    def to_json(self) -> dict:
        """
        Serializes the Dashboard instance to a JSON-compatible dictionary.

        :return: A dictionary representation of the Dashboard.
        """
        ...

    def from_json(self, data: dict) -> "DashboardProtocol":
        """
        Deserializes a Dashboard instance from a JSON-compatible dictionary.

        :param data: A dictionary representation of the Dashboard.
        """
        ...

    def layout(self) -> Component:
        """
        Renders the layout component for the dashboard.

        :return: The Dash layout component to be displayed.
        :rtype: Component
        """
        ...
