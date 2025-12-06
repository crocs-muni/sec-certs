"""
Component ID helper for dashboard callbacks.

This module provides a simple helper for creating consistent component IDs
across dashboard callbacks, eliminating string formatting boilerplate.
"""

from enum import Enum
from typing import Any


class ComponentID(str, Enum):
    """Enumeration of dashboard component ID suffixes.

    These suffixes are combined with collection_name prefixes to create
    full component IDs like "cc-dashboard-selector", "fips-create-dashboard-btn", etc.
    """

    # Dashboard management
    SELECTOR = "dashboard-selector"
    CREATE_BTN = "create-dashboard-btn"
    DELETE_BTN = "delete-dashboard-btn"
    SAVE_BTN = "save-dashboard-btn"

    # Dashboard state and UI
    EMPTY_STATE = "empty-state"
    DASHBOARD_CONTENT = "dashboard-content"
    CURRENT_DASHBOARD_ID = "current-dashboard-id"
    DASHBOARD_NAME_INPUT = "dashboard-name-input"
    DASHBOARD_LOADED = "dashboard-loaded"
    COLLECTION_NAME = "collection-name"
    DASHBOARD_TOAST = "dashboard-toast"

    # Chart management
    CHART_CONFIGS_STORE = "chart-configs-store"
    CHART = "chart"
    CHART_DELETE_BTN = "chart-delete-btn"
    ADD_CHART_BTN = "add-chart-btn"
    CHART_SELECTOR = "chart-selector"
    CHART_CONTAINER = "chart-container"
    RENDER_TRIGGER = "render-trigger"
    UPDATE_ALL_BTN = "update-all-btn"
    FILTER_STORE = "filter-store"

    # Modal components
    MODAL = "modal"
    MODAL_CLOSE = "modal-close"
    MODAL_OPEN = "modal-open"
    MODAL_CONFIRM = "modal-confirm"
    CREATE_CHART_MODAL = "create-chart-modal"
    OPEN_CREATE_CHART_MODAL_BTN = "open-create-chart-modal-btn"
    MODAL_CANCEL_BTN = "modal-cancel-btn"
    EDIT_CHART_ID = "edit-chart-id"
    MODAL_TITLE = "modal-title"
    MODAL_CREATE_BTN = "modal-create-btn"
    MODAL_CHART_TITLE = "modal-chart-title"
    MODAL_CHART_TYPE = "modal-chart-type"
    MODAL_X_FIELD = "modal-x-field"
    MODAL_X_LABEL = "modal-x-label"
    MODAL_COLOR_FIELD = "modal-color-field"
    MODAL_AGGREGATION = "modal-aggregation"
    MODAL_Y_FIELD = "modal-y-field"
    MODAL_Y_LABEL = "modal-y-label"
    MODAL_SHOW_LEGEND = "modal-show-legend"
    MODAL_SHOW_GRID = "modal-show-grid"
    COLOR_BY_COLLAPSE = "color-by-collapse"
    MODAL_FILTERS_CONTAINER = "modal-filters-container"
    MODAL_FILTERS_READY = "modal-filters-ready"
    FILTER_SPECS = "filter-specs"
    AVAILABLE_FIELDS = "available-fields"
    MODAL_Y_FIELD_HELP = "modal-y-field-help"
    CHART_TYPE_HELP = "chart-type-help"
    COLOR_BY_ICON = "color-by-icon"
    COLOR_BY_TOGGLE = "color-by-toggle"
    MODAL_VALIDATION_ALERT = "modal-validation-alert"

    # Pattern-matching component types (used in dicts)
    CHART_CONTENT = "chart-content"
    CHART_REFRESH = "chart-refresh"
    CHART_WRAPPER = "chart-wrapper"
    REMOVE_CHART = "remove-chart"
    CHART_EDIT = "chart-edit"
    MODAL_FILTER = "modal-filter"
    CLEAR_FILTER = "clear-filter"
    SELECT_ALL_FILTER = "select-all-filter"


class ComponentIDBuilder:
    """Helper for creating component IDs with collection_name prefixes.

    This class eliminates f-string formatting boilerplate when creating component IDs.
    It only creates ID strings - use them directly with Dash Input/Output/State.
    """

    def __init__(self, collection_name: str | None) -> None:
        """Initialize the ID builder.

        :param collection_name: The collection name prefix (e.g., "cc", "fips").
                               If empty, component IDs will be used without prefix.
        :type collection_name: str
        """
        self.collection_name = collection_name

    def __call__(self, component: ComponentID) -> str | dict[str, Any]:
        """Create a component ID with collection_name prefix.

        :param component: The component ID suffix from ComponentID enum.
        :type component: ComponentID
        :return: Full component ID string like "cc-dashboard-selector".
        :rtype: str
        """
        if self.collection_name:
            return f"{self.collection_name}-{component}"
        return component.value


class PatternMatchingComponentID(ComponentIDBuilder):
    """Helper for creating pattern-matching component IDs with type/index dictionaries.

    Extends ComponentIDBuilder to create dictionary-based IDs for Dash pattern-matching
    callbacks using wildcards like MATCH, ALL, ALLSMALLER.
    """

    def __call__(
        self,
        component: ComponentID,
        index: Any = None,
        use_prefix: bool = False,
        index_key: str = "index",
    ) -> dict[str, Any] | str:
        """Create a pattern-matching component ID dictionary or string ID.

        :param component: The component type from ComponentID enum.
        :type component: ComponentID
        :param index: The index value (MATCH, ALL, ALLSMALLER, or specific value).
                     If None, returns a simple string ID (calls parent).
        :type index: Any, optional
        :param use_prefix: If True, prepends collection_name to the component type.
                          Only used when index is not None.
        :type use_prefix: bool
        :param index_key: The key name for the index in the dict (default: "index").
                         Can be "field" for filters, etc.
        :type index_key: str
        :return: If index is None: string ID (e.g., "cc-dashboard-selector").
                If index is not None: dict ID (e.g., {"type": "chart-content", "index": MATCH}).
        :rtype: dict[str, Any] | str

        """
        if index is None:
            # No pattern matching - return simple string ID
            return super().__call__(component)

        # Pattern matching - return dict ID
        type_value = component.value
        if use_prefix and self.collection_name:
            type_value = f"{self.collection_name}-{component}" if self.collection_name else component.value

        return {"type": type_value, index_key: index}
