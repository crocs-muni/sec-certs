from typing import Any, cast

import dash_bootstrap_components as dbc
from dash import dcc, html
from dash.dependencies import Input
from dash.development.base_component import Component

from ..types.common import CollectionName
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

    def __init__(self, dataset_type: CollectionName):
        self.dataset_type = dataset_type
        self._registry = get_filter_registry(dataset_type)

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
        component_id = f"{self.dataset_type.value}-filter-{filter_spec.id}"
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
        return [f"{self.dataset_type.value}-filter-{spec.id}" for spec in self._registry.get_all_filters().values()]

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
