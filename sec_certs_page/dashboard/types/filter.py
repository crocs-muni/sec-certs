from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, TypedDict

from typing_extensions import NotRequired


class AggregationType(str, Enum):
    COUNT = "count"
    SUM = "sum"
    AVG = "avg"
    MIN = "min"
    MAX = "max"


class FilterOperator(str, Enum):
    """MongoDB query operators."""

    EQ = "$eq"
    NE = "$ne"
    GT = "$gt"
    GTE = "$gte"
    LT = "$lt"
    LTE = "$lte"
    IN = "$in"
    NIN = "$nin"
    REGEX = "$regex"
    EXISTS = "$exists"


class FilterComponentType(str, Enum):
    """UI component types for filters."""

    DROPDOWN = "dropdown"
    MULTI_DROPDOWN = "multi_dropdown"
    TEXT_SEARCH = "text_search"
    DATE_PICKER = "date_picker"
    DATE_RANGE = "date_range"
    CHECKBOX = "checkbox"


@dataclass
class DashFilterComponentParams:
    """Metadata for generating Dash UI components."""

    component_type: FilterComponentType
    label: str
    placeholder: str | None = None
    min_value: int | float | str | None = None
    max_value: int | float | str | None = None
    default_value: Any | None = None
    help_text: str | None = None
    multi: bool = False
    clearable: bool = True
    searchable: bool = False


class FilterSpecDict(TypedDict):
    """Filter specification dictionary for serialization."""

    id: str
    database_field: str
    operator: FilterOperator
    data_type: str
    component_params: DashFilterComponentParams
    data: NotRequired[Any]
    transform: NotRequired[Callable]
    mongodb_pipeline: NotRequired[list[dict]]
