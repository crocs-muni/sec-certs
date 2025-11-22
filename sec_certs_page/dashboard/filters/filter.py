from dataclasses import dataclass
from typing import Any, Callable

from sec_certs_page.dashboard.types.filter import (
    AggregationType,
    DashFilterComponentParams,
    FilterOperator,
    FilterSpecDict,
)


@dataclass
class FilterSpec:
    """Filter specification for MongoDB queries and Dash UI components.

    This dataclass serves as a pure configuration object (data only, no behavior)
    that defines how a filter should work. Query building logic is handled by
    QueryBuilder, and UI generation is handled by DashFilterFactory.

    :param filter_id: Unique identifier (used for both Dash component ID and query key)
    :param database_field: MongoDB document field name
    :param operator: MongoDB operator for queries
    :param data_type: Data type as string for validation
    :param data: Fetched data from database for filter options or available values (min, max, etc.)
    :param component_params: Metadata for generating Dash component
    :param transform: Optional value transformation before query
    :param options: Whether to load options from database (for dropdowns)
    """

    id: str
    database_field: str
    operator: FilterOperator
    data_type: str
    component_params: DashFilterComponentParams
    active: bool = False
    data: Any | None = None
    transform: Callable | None = None
    mongodb_pipeline: list[dict] | None = None
    aggregation: AggregationType | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize filter configuration to dictionary."""
        return {
            "filter_id": self.id,
            "type": self.component_params.component_type.value,
            "value": None,
            "active": self.active,
            "aggregation": self.aggregation.value if self.aggregation else None,
        }

    @classmethod
    def from_dict(cls, data: FilterSpecDict) -> "FilterSpec":
        """Create FilterSpec instance from dictionary."""
        return cls(
            id=data["id"],
            database_field=data["database_field"],
            operator=data["operator"],
            data_type=data["data_type"],
            component_params=data["component_params"],
            data=None,
            aggregation=data.get("aggregation"),
        )
