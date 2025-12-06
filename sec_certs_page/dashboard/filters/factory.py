from typing import Any, cast

import dash_bootstrap_components as dbc
from dash import dcc, html
from dash.dependencies import Input
from dash.development.base_component import Component

from ..types.common import CollectionType
from ..types.filter import FilterComponentType
from .filter import FilterSpec
from .registry import FilterSpecRegistry, get_filter_registry

DBC_GRID_COL_MAX_WIDTH = 12
"""Maximum width for a column in Dash Bootstrap Components grid system."""


class FilterFactory:
    """
    Factory for creating filter UI components.

    Responsible for generating Dash components from FilterSpec definitions,
    including proper labels, styling, and component IDs for callback binding.
    """

    def __init__(self, collection_type: CollectionType):
        self.collection_type = collection_type
        self._registry = get_filter_registry(collection_type)

    @property
    def registry(self) -> type[FilterSpecRegistry]:
        """Get the filter registry for this dataset type."""
        return self._registry

    def create_filter(self, filter_spec: FilterSpec, with_label: bool = True) -> Component:
        """
        Create a single filter component from its specification.

        :param filter_spec: Filter specification
        :param with_label: Whether to include a label
        :return: Dash component for the filter
        """
        component_id = f"{self.collection_type.value}-filter-{filter_spec.id}"
        params = filter_spec.component_params

        if params.component_type == FilterComponentType.DROPDOWN:
            # Build options from filter data if available
            options: list[dict[str, Any]] = []
            if filter_spec.data:
                options = [{"label": str(v), "value": v} for v in filter_spec.data]

            filter_component = dcc.Dropdown(
                id=component_id,
                options=options,  # type: ignore[arg-type]
                placeholder=params.placeholder or f"Select {params.label}...",
                multi=params.multi,
                clearable=params.clearable,
                searchable=params.searchable,
                value=params.default_value,
                className="dash-bootstrap",
            )
        elif params.component_type == FilterComponentType.MULTI_DROPDOWN:
            options = []
            if filter_spec.data:
                options = [{"label": str(v), "value": v} for v in filter_spec.data]

            filter_component = dcc.Dropdown(
                id=component_id,
                options=options,  # type: ignore[arg-type]
                placeholder=params.placeholder or f"Select {params.label}...",
                multi=True,
                clearable=params.clearable,
                searchable=params.searchable,
                value=params.default_value,
                className="dash-bootstrap",
            )
        elif params.component_type == FilterComponentType.DATE_RANGE:
            filter_component = dcc.DatePickerRange(
                id=component_id,
                min_date_allowed=cast(str | None, params.min_value),
                max_date_allowed=cast(str | None, params.max_value),
                className="dash-bootstrap",
            )
        elif params.component_type == FilterComponentType.DATE_PICKER:
            filter_component = dcc.DatePickerSingle(
                id=component_id,
                min_date_allowed=cast(str | None, params.min_value),
                max_date_allowed=cast(str | None, params.max_value),
                date=params.default_value,
                className="dash-bootstrap",
            )
        elif params.component_type == FilterComponentType.TEXT_SEARCH:
            filter_component = dbc.Input(
                id=component_id,
                type="text",
                placeholder=params.placeholder or f"Search {params.label}...",
                value=params.default_value or "",
            )
        elif params.component_type == FilterComponentType.CHECKBOX:
            filter_component = dbc.Checkbox(
                id=component_id,
                label=params.label,
                value=params.default_value or False,
            )
        else:
            filter_component = html.Span(f"Unknown filter type: {params.component_type}", className="text-danger")

        if with_label and params.component_type != FilterComponentType.CHECKBOX:
            return html.Div(
                className="mb-3",
                children=[
                    dbc.Label(params.label, html_for=component_id, className="fw-bold"),
                    filter_component,
                    html.Small(params.help_text, className="text-muted") if params.help_text else None,
                ],
            )

        return filter_component

    def create_all_filters(self, with_labels: bool = True) -> list[Component]:
        """
        Create all registered filters for this dataset type.

        :param with_labels: Whether to include labels
        :return: List of filter components
        """
        return [self.create_filter(spec, with_labels) for spec in self._registry.get_all_filters().values()]

    def create_filter_panel(self, title: str = "Filters", columns: int = 4) -> dbc.Card:
        """
        Create a complete filter panel with all filters in a Bootstrap card.

        :param title: Panel title
        :param columns: Maximum number of filters per row
        :return: Card with all filters
        """
        filters = self.create_all_filters(with_labels=True)
        col_width = DBC_GRID_COL_MAX_WIDTH // columns

        rows = []
        for i in range(0, len(filters), columns):
            row_filters = filters[i : i + columns]
            cols = [dbc.Col(filter_comp, width=12, md=col_width) for filter_comp in row_filters]
            rows.append(dbc.Row(cols, className="g-3"))

        return dbc.Card(
            className="mb-4",
            children=[
                dbc.CardHeader(
                    html.H4([html.I(className="fas fa-filter me-2"), title], className="mb-0"),
                ),
                dbc.CardBody(children=rows if rows else [html.P("No filters available.", className="text-muted")]),
            ],
        )

    def get_filter_ids(self) -> list[str]:
        """
        Get all filter component IDs for callback registration.

        :return: List of filter component IDs
        """
        return [f"{self.collection_type.value}-filter-{spec.id}" for spec in self._registry.get_all_filters().values()]

    def create_callback_inputs(self) -> list[Input]:
        """
        Create Dash Input dependencies for all filters.

        Used to register callbacks that respond to filter value changes.

        :return: List of Dash Input dependencies
        """
        inputs = []
        for filter_id in self.get_filter_ids():
            inputs.append(Input(filter_id, "value"))
        return inputs

    def collect_filter_values(self, *filter_values: Any) -> dict[str, Any]:
        """
        Collect filter values into a dictionary keyed by filter ID.

        This method is designed to be called from a callback with values
        from all filter inputs. It pairs each value with its filter ID.

        :param filter_values: Values from filter components in order
        :return: Dictionary mapping filter IDs to their current values
        """
        filter_ids = self.get_filter_ids()
        result = {}

        for filter_id, value in zip(filter_ids, filter_values):
            # Only include non-empty values
            if value is not None and value != "" and value != []:
                result[filter_id] = value

        return result

    def get_available_fields(self) -> list[dict[str, str]]:
        """
        Get available fields for chart axis selection.

        Returns a list of field options derived from registered FilterSpecs,
        plus commonly used derived fields (like year_from).
        Each field can be used for grouping (X-axis) or aggregation (Y-axis).

        :return: List of dicts with 'label', 'value', and 'data_type' keys
        """
        fields = []
        # Track fields we've already added to avoid duplicates
        seen_fields = set()

        for filter_spec in self._registry.get_all_filters().values():
            # Skip date fields that are better represented as derived year fields
            # (e.g., prefer year_from over not_valid_before for grouping)
            if filter_spec.database_field in ("not_valid_before", "not_valid_after"):
                continue

            # Skip if we've already added this database field
            if filter_spec.database_field in seen_fields:
                continue

            seen_fields.add(filter_spec.database_field)
            fields.append(
                {
                    "label": filter_spec.component_params.label,
                    "value": filter_spec.database_field,
                    "data_type": filter_spec.data_type,
                }
            )

        # Add derived fields that are computed in the DataFrame
        # These are available for charting but require special handling for filtering
        derived_fields = self._get_derived_fields()
        fields.extend(derived_fields)

        return fields

    def _get_derived_fields(self) -> list[dict[str, str]]:
        """
        Get derived fields that are computed from other fields.

        These fields are computed in the DataFrame (e.g., year extracted from date)
        and can be used for chart grouping. For filtering, they may require
        special MongoDB aggregation expressions.

        :return: List of derived field definitions
        """
        if self.collection_type == CollectionType.CommonCriteria:
            return [
                {
                    "label": "Certificate Year",
                    "value": "year_from",
                    "data_type": "int",
                    "derived_from": "not_valid_before",  # Source field
                },
            ]
        elif self.collection_type == CollectionType.FIPS140:
            return [
                {
                    "label": "Validation Year",
                    "value": "year_from",
                    "data_type": "int",
                    "derived_from": "date_validation",  # Source field
                },
            ]
        return []

    def get_numeric_fields(self) -> list[dict[str, str]]:
        """
        Get numeric fields for Y-axis aggregation (SUM, AVG, MIN, MAX).

        Only numeric fields can be aggregated with mathematical operations.
        COUNT aggregation doesn't require a specific field.

        :return: List of dicts with 'label' and 'value' keys for numeric fields
        """
        numeric_types = {"int", "float", "number", "numeric"}
        return [
            {"label": f["label"], "value": f["value"]}
            for f in self.get_available_fields()
            if f["data_type"].lower() in numeric_types
        ]

    def get_filter_specs_for_modal(self) -> list[dict[str, Any]]:
        """
        Get filter specifications for the chart creation modal.

        Returns serializable filter metadata that can be used to create
        filter UI components dynamically in the modal.

        :return: List of dicts with filter metadata for modal population
        """
        specs = []
        for filter_id, filter_spec in self._registry.get_all_filters().items():
            specs.append(
                {
                    "id": filter_id,
                    "label": filter_spec.component_params.label,
                    "field": filter_spec.database_field,
                    "operator": filter_spec.operator.value,
                    "data_type": filter_spec.data_type,
                    "component_type": filter_spec.component_params.component_type.value,
                    "placeholder": filter_spec.component_params.placeholder,
                    "help_text": filter_spec.component_params.help_text,
                }
            )
        return specs
