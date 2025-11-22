from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable


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


class FilterUIType(str, Enum):
    """UI component types for filters."""

    DROPDOWN = "dropdown"
    MULTI_DROPDOWN = "multi_dropdown"
    TEXT_SEARCH = "text_search"
    DATE_PICKER = "date_picker"
    DATE_RANGE = "date_range"
    RANGE_SLIDER = "range_slider"
    CHECKBOX = "checkbox"


@dataclass
class UIMetadata:
    """Metadata for generating Dash UI components.

    This dataclass contains all information needed to render a filter
    as a Dash component, separate from MongoDB query logic.

    :param ui_type: Type of UI component to generate
    :param label: Human-readable label for the filter
    :param placeholder: Placeholder text (for text inputs)
    :param options: Available options (for dropdowns)
    :param min_value: Minimum value (for sliders/date pickers)
    :param max_value: Maximum value (for sliders/date pickers)
    :param default_value: Default/initial value
    :param help_text: Tooltip or help text
    :param multi: Allow multiple selections (dropdowns)
    :param clearable: Allow clearing selection
    :param searchable: Enable search in dropdown
    """

    ui_type: FilterUIType
    label: str
    placeholder: str | None = None
    options: list | dict[str, Any] | None = None  # [{'label': 'X', 'value': 'X'}]
    min_value: int | float | str | None = None
    max_value: int | float | str | None = None
    default_value: Any | None = None
    help_text: str | None = None
    multi: bool = False
    clearable: bool = True
    searchable: bool = False


@dataclass
class FilterSpec:
    """Filter specification for MongoDB queries and Dash UI components.

    This dataclass serves as a pure configuration object (data only, no behavior)
    that defines how a filter should work. Query building logic is handled by
    QueryBuilder, and UI generation is handled by DashFilterFactory.

    :param filter_id: Unique identifier (used for both Dash component ID and query key)
    :param mongodb_field: MongoDB document field name
    :param operator: MongoDB operator for queries
    :param data_type: Python type for validation
    :param ui_metadata: Metadata for generating Dash component
    :param transform: Optional value transformation before query
    :param lazy_load_options: Whether to load options from database (for dropdowns)
    :param label_map: Optional mapping for custom option labels
    """

    id: str
    mongodb_field: str
    operator: FilterOperator
    data_type: type
    ui_metadata: UIMetadata
    transform: Callable | None = None
    lazy_load_options: bool = False
    label_map: dict[str, str] | None = None
