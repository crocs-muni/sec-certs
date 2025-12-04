import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .chart.config import ChartConfig
from .types.common import CollectionName

# Namespace UUID for dashboard IDs - ensures deterministic UUID5 generation
# Generated once using uuid.uuid4() to serve as a consistent namespace
DASHBOARD_NAMESPACE = uuid.UUID("a62bec37-23e6-4120-88dc-61370a58e73c")


def _generate_dashboard_id(user_id: str, collection_name: str, created_at: datetime) -> uuid.UUID:
    """
    Generate deterministic UUID5 for a dashboard based on its unique identifiers.

    Uses user_id, collection_name, and creation timestamp to ensure uniqueness
    while allowing users to have multiple dashboards with the same name.

    :param user_id: The user who owns the dashboard
    :param collection_name: The collection name (cc, fips)
    :param created_at: The creation timestamp
    :return: A UUID5 generated from the namespace and dashboard identifiers
    """
    timestamp_str = created_at.isoformat()
    identifier = f"{user_id}:{collection_name}:{timestamp_str}"
    return uuid.uuid5(DASHBOARD_NAMESPACE, identifier)


def _parse_datetime(dt_string: str) -> datetime:
    """
    Parse a datetime string handling various timezone formats.

    Handles:
    - 'Z' suffix (UTC)
    - '+00:00' timezone offset
    - Corrupted double timezone like '+00:00+00:00'

    :param dt_string: ISO format datetime string
    :return: Parsed datetime object with UTC timezone
    """
    # Handle corrupted double timezone (from previous bug)
    while "+00:00+00:00" in dt_string:
        dt_string = dt_string.replace("+00:00+00:00", "+00:00")

    # Remove 'Z' suffix if present and replace with +00:00
    if dt_string.endswith("Z"):
        dt_string = dt_string[:-1] + "+00:00"

    return datetime.fromisoformat(dt_string)


@dataclass
class Dashboard:
    """
    Represents a dashboard configuration for a specific dataset type.
    Uses UUID5 for deterministic IDs based on user id, collection name, and creation timestamp.
    """

    dashboard_id: uuid.UUID = field(init=False)
    user_id: str
    collection_name: CollectionName
    name: str = "New dashboard"
    description: str | None = None
    charts: list[ChartConfig] = field(default_factory=list)
    is_default: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self):
        """Generate deterministic UUID5 after initialization."""
        self.dashboard_id = _generate_dashboard_id(self.user_id, str(self.collection_name), self.created_at)

    def to_json(self) -> dict:
        """Serializes the Dashboard instance to a JSON-compatible dictionary."""
        return {}

    def add_chart(self, chart: ChartConfig) -> None:
        """
        Add a chart to the dashboard.

        Chart is appended to end of list. Use reorder_chart() to change position.
        """
        self.charts.append(chart)
        self.updated_at = datetime.now(timezone.utc)

    def remove_chart(self, chart_id: str) -> ChartConfig:
        """
        Remove a chart from the dashboard.

        :param chart_id: ID of chart to remove
        :type chart_id: str

        :return: The removed chart
        :rtype: Chart

        :raises ValueError: If chart_id not found
        """
        target_id = uuid.UUID(chart_id)
        for i, chart in enumerate(self.charts):
            if chart.chart_id == target_id:
                removed = self.charts.pop(i)
                self.updated_at = datetime.now(timezone.utc)
                return removed

        raise ValueError(f"Chart with id {chart_id} not found")

    def get_chart(self, chart_id: str) -> ChartConfig | None:
        """
        Get a chart by ID.

        :param chart_id: ID of chart to retrieve
        :type chart_id: str

        :return: Chart if found, None otherwise
        :rtype: Chart or None
        """
        target_id = uuid.UUID(chart_id)
        for chart in self.charts:
            if chart.chart_id == target_id:
                return chart
        return None

    def update_chart(self, chart: ChartConfig) -> None:
        """
        Update an existing chart.

        :param chart: Updated chart (must have existing chart_id)
        :type chart: Chart

        :raises ValueError: If chart not found in dashboard
        """
        for i, existing in enumerate(self.charts):
            if existing.chart_id == chart.chart_id:
                self.charts[i] = chart
                self.updated_at = datetime.now(timezone.utc)
                return

        raise ValueError(f"Chart {chart.chart_id} not found in dashboard")

    def clear_charts(self) -> None:
        """
        Remove all charts from dashboard.
        """
        self.charts.clear()
        self.updated_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize dashboard to JSON-compatible dictionary.

        :return: Complete dashboard configuration including all charts
        :rtype: dict[str, Any]
        """
        return {
            "dashboard_id": str(self.dashboard_id),
            "user_id": self.user_id,
            "collection_name": self.collection_name.value,
            "name": self.name,
            "description": self.description,
            "charts": [chart.to_dict() for chart in self.charts],
            "is_default": self.is_default,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Dashboard":
        """
        Deserialize dashboard from dictionary representation.

        This method is only called from DashboardRepository when loading
        from MongoDB, so we can trust the query_pipeline in the stored chart configs.

        :param data: Serialized dashboard data (from MongoDB)
        :type data: dict[str, Any]

        :return: Reconstructed dashboard instance with all charts
        :rtype: Dashboard

        :raises ValueError: If data is invalid or incomplete
        """
        required = ["dashboard_id", "user_id", "collection_name", "name"]
        missing = [f for f in required if f not in data]
        if missing:
            raise ValueError(f"Missing required fields: {missing}")

        # this is only called from database reads
        charts = [ChartConfig.from_dict(chart_data, trust_pipeline=True) for chart_data in data.get("charts", [])]

        created_at_str = data.get("created_at", "")
        updated_at_str = data.get("updated_at", "")

        created_at = _parse_datetime(created_at_str) if created_at_str else datetime.now(timezone.utc)
        updated_at = _parse_datetime(updated_at_str) if updated_at_str else datetime.now(timezone.utc)

        collection_name = CollectionName(data["collection_name"])

        dashboard = cls(
            user_id=data["user_id"],
            collection_name=collection_name,
            name=data["name"],
            description=data.get("description", ""),
            charts=charts,
            is_default=data.get("is_default", False),
            created_at=created_at,
            updated_at=updated_at,
        )

        return dashboard

    def __repr__(self) -> str:
        """
        String representation for debugging.

        :return: Human-readable representation of the Dashboard
        :rtype: str
        """
        return (
            f"Dashboard(id={str(self.dashboard_id)[:8]}..., name='{self.name}', "
            f"collection={self.collection_name}, charts={len(self.charts)})"
        )
