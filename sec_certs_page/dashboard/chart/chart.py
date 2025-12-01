from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from ..filters.filter import FilterSpec
from ..types.chart import AvailableChartTypes
from ..types.common import CollectionName
from ..types.filter import AggregationType


@dataclass
class AxisConfig:
    """Configuration for a single axis (X or Y).

    :param field: Dataset field name to plot (e.g., "category", "year_from")
    :type field: str
    :param label: Display label shown on axis (can be customized by user)
    :type label: str
    :param aggregation: Aggregation function for Y-axis (COUNT, SUM, AVG, MIN, MAX).
                        Only applicable for Y-axis; X-axis should leave as None.
    :type aggregation: AggregationType | None
    """

    field: str
    label: str
    aggregation: AggregationType | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize axis configuration to dictionary.

        :return: JSON-serializable dictionary containing field, label, and aggregation
        :rtype: dict[str, Any]
        """
        return {
            "field": self.field,
            "label": self.label,
            "aggregation": self.aggregation,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AxisConfig":
        """Deserialize axis configuration from dictionary.

        :param data: Serialized axis configuration
        :type data: dict[str, Any]
        :return: Reconstructed axis configuration instance
        :rtype: AxisConfig
        """
        return cls(
            field=data["field"],
            label=data["label"],
            aggregation=data.get("aggregation"),
        )


@dataclass
class Chart:
    """Represents a single chart configuration within a dashboard.

    A Chart defines what data to display, how to filter it, and how to visualize it.
    Charts are persisted to MongoDB and reconstructed on dashboard load.

    :param chart_id: Unique identifier for this chart (UUID4)
    :type chart_id: UUID
    :param name: Internal name for chart (used in code/logs)
    :type name: str
    :param chart_type: Visualization type (BAR, LINE, PIE, SCATTER, BOX, HISTOGRAM)
    :type chart_type: AvailableChartTypes
    :param x_axis: X-axis configuration (field, label, aggregation)
    :type x_axis: AxisConfig
    :param title: User-facing display title shown above the chart
    :type title: str
    :param order: Display order within dashboard (0-indexed, lower values appear first)
    :type order: int
    :param y_axis: Y-axis configuration (None for single-axis charts like PIE)
    :type y_axis: AxisConfig | None
    :param filters: Active filters for this chart (keyed by filter ID)
    :type filters: dict[str, FilterSpec]
    :param query_pipeline: Cached MongoDB aggregation pipeline (built by QueryBuilder)
    :type query_pipeline: list[dict[str, Any]] | None
    :param color_scheme: Plotly color scheme name
    :type color_scheme: str
    :param show_legend: Whether to display chart legend
    :type show_legend: bool
    :param show_grid: Whether to display grid lines
    :type show_grid: bool
    :param created_at: Timestamp when chart was created (UTC)
    :type created_at: datetime | None
    :param updated_at: Timestamp of last modification (UTC)
    :type updated_at: datetime | None
    """

    chart_id: UUID
    name: str
    chart_type: AvailableChartTypes
    x_axis: AxisConfig
    collection_type: CollectionName
    title: str = ""
    order: int = 0
    y_axis: AxisConfig | None = None
    color_axis: AxisConfig | None = None
    filters: dict[str, FilterSpec] = field(default_factory=dict)
    filter_values: dict[str, Any] = field(default_factory=dict)
    query_pipeline: list[dict[str, Any]] | None = None
    color_scheme: str = "plotly"
    show_legend: bool = True
    show_grid: bool = True
    created_at: datetime | None = None
    updated_at: datetime | None = None

    def add_filter(self, filter_config: FilterSpec) -> None:
        """Add or update a filter configuration.

        If a filter with the same ID already exists, it is replaced.
        Updates the chart's modification timestamp.

        :param filter_config: Filter configuration to add or update
        :type filter_config: FilterSpec
        """
        self.filters[filter_config.id] = filter_config
        self.updated_at = datetime.now(timezone.utc)

    def remove_filter(self, filter_id: str) -> None:
        """Remove a filter configuration.

        :param filter_id: ID of filter to remove
        :type filter_id: str
        :raises KeyError: If filter_id not found in chart's filters
        """
        del self.filters[filter_id]
        self.updated_at = datetime.now(timezone.utc)

    def get_active_filters(self) -> dict[str, FilterSpec]:
        """Get only the filters that are currently active.

        :return: Dictionary of active filters (where filter.active == True)
        :rtype: dict[str, FilterSpec]

        .. note::
           This is used by QueryBuilder to construct the MongoDB query.
           Inactive filters are stored but not applied to data retrieval.
        """
        return {fid: filter_spec for fid, filter_spec in self.filters.items() if filter_spec.active}

    def set_query_pipeline(self, pipeline: list[dict[str, Any]]) -> None:
        """Set the MongoDB query pipeline for this chart.

        The pipeline is built externally (by QueryBuilder) based on active filters
        and chart configuration. It is cached here to avoid rebuilding on every render.

        :param pipeline: MongoDB aggregation pipeline stages
        :type pipeline: list[dict[str, Any]]
        """
        self.query_pipeline = pipeline
        self.updated_at = datetime.now(timezone.utc)

    def get_query_pipeline(self) -> list[dict[str, Any]] | None:
        """Get the stored MongoDB query pipeline.

        :return: Cached MongoDB aggregation pipeline, or None if not yet built
        :rtype: list[dict[str, Any]] | None
        """
        return self.query_pipeline

    def to_dict(self) -> dict[str, Any]:
        """Serialize chart to JSON-compatible dictionary.

        This method produces the complete chart configuration for MongoDB persistence.
        The returned dictionary must be JSON-serializable and contain everything
        needed to recreate the chart on deserialization.

        :return: Complete chart configuration as dictionary
        :rtype: dict[str, Any]
        """
        # Handling Z in isoformat because python3.10 can't handle it
        return {
            "chart_id": str(self.chart_id),
            "name": self.name,
            "title": self.title,
            "order": self.order,
            "chart_type": self.chart_type.value,
            "collection_type": self.collection_type.value,
            "x_axis": self.x_axis.to_dict(),
            "y_axis": self.y_axis.to_dict() if self.y_axis else None,
            "color_axis": self.color_axis.to_dict() if self.color_axis else None,
            "filters": {fid: fconfig.to_dict() for fid, fconfig in self.filters.items()},
            "filter_values": self.filter_values,
            "query_pipeline": self.query_pipeline,
            "color_scheme": self.color_scheme,
            "show_legend": self.show_legend,
            "show_grid": self.show_grid,
            "created_at": self.created_at.isoformat() + "Z" if self.created_at else None,
            "updated_at": self.updated_at.isoformat() + "Z" if self.updated_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Chart":
        """Deserialize chart from dictionary representation.

        Reconstructs a Chart instance from MongoDB document or serialized state.
        Validates required fields and handles optional fields gracefully.

        :param data: Serialized chart data (typically from MongoDB)
        :type data: dict[str, Any]
        :return: Reconstructed chart instance with all nested objects
        :rtype: Chart
        :raises ValueError: If required fields are missing from data
        """
        required = ["chart_id", "name", "chart_type", "collection_type", "x_axis"]
        missing = [f for f in required if f not in data]
        if missing:
            raise ValueError(f"Missing required fields: {missing}")

        x_axis = AxisConfig.from_dict(data["x_axis"])
        y_axis = AxisConfig.from_dict(data["y_axis"]) if data.get("y_axis") else None
        color_axis = AxisConfig.from_dict(data["color_axis"]) if data.get("color_axis") else None

        filters = {fid: FilterSpec.from_dict(fdata) for fid, fdata in data.get("filters", {}).items()}

        # Handling Z in isoformat because python3.10 can't handle it
        created_at = (
            datetime.fromisoformat(data["created_at"].replace("Z", "+00:00")) if data.get("created_at") else None
        )
        updated_at = (
            datetime.fromisoformat(data["updated_at"].replace("Z", "+00:00")) if data.get("updated_at") else None
        )

        chart_id = data["chart_id"]
        if isinstance(chart_id, str):
            chart_id = UUID(chart_id)

        chart_type = data["chart_type"]
        if isinstance(chart_type, str):
            chart_type = AvailableChartTypes(chart_type)

        collection_type = data["collection_type"]
        if isinstance(collection_type, str):
            collection_type = CollectionName(collection_type)

        return cls(
            chart_id=chart_id,
            name=data["name"],
            title=data.get("title", ""),
            order=data.get("order", 0),
            chart_type=chart_type,
            collection_type=collection_type,
            x_axis=x_axis,
            y_axis=y_axis,
            color_axis=color_axis,
            filters=filters,
            filter_values=data.get("filter_values", {}),
            query_pipeline=data.get("query_pipeline"),
            color_scheme=data.get("color_scheme", "plotly"),
            show_legend=data.get("show_legend", True),
            show_grid=data.get("show_grid", True),
            created_at=created_at,
            updated_at=updated_at,
        )

    def __repr__(self) -> str:
        """String representation for debugging.

        :return: Human-readable representation showing key chart attributes
        :rtype: str
        """
        # Convert UUID to string and take first 8 characters for brevity
        chart_id_str = str(self.chart_id)[:8] if self.chart_id else "None"
        return (
            f"Chart(id={chart_id_str}..., name='{self.name}', " f"type={self.chart_type}, filters={len(self.filters)})"
        )
