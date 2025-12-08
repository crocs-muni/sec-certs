from dataclasses import dataclass
from typing import Any, Callable

from ..types.filter import FilterComponentParams, FilterOperator


@dataclass
class FilterSpec:
    """Filter specification for MongoDB queries and Dash UI components.

    This dataclass serves as a pure configuration object (data only, no behavior)
    that defines how a filter should work. Query building logic is handled by
    QueryBuilder, and UI generation is handled by DashFilterFactory.

    FilterSpecs also serve as the source of available fields for chart axis selection,
    since each FilterSpec corresponds to a database column.

    :param id: Unique identifier (used for both Dash component ID and query key)
    :param database_field: MongoDB document field name
    :param operator: MongoDB operator for queries
    :param data_type: Data type as string for validation (e.g., "str", "int", "date")
    :param component_params: Metadata for generating Dash component
    :param active: Whether this filter is currently active
    :param data: Fetched data from database for filter options or available values
    :param transform: Optional value transformation before query
    :param mongodb_pipeline: Custom MongoDB aggregation pipeline stages
    """

    id: str
    database_field: str
    operator: FilterOperator
    data_type: str
    component_params: FilterComponentParams
    active: bool = False
    data: Any | None = None
    transform: Callable | None = None
    mongodb_pipeline: list[dict] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize filter configuration to dictionary."""
        return {
            "filter_id": self.id,
            "type": self.component_params.component_type.value,
            "value": None,
            "active": self.active,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FilterSpec":
        """Create FilterSpec instance from dictionary."""
        return cls(
            id=data["id"],
            database_field=data["database_field"],
            operator=data["operator"],
            data_type=data["data_type"],
            component_params=data["component_params"],
            data=None,
        )
