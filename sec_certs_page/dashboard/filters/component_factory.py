from typing import Any

import dash_bootstrap_components as dbc
from dash import dcc, html
from dash.development.base_component import Component

from sec_certs_page.dashboard.filters.filter import FilterSpec
from sec_certs_page.dashboard.filters.registry import get_filter_registry
from sec_certs_page.dashboard.types.common import CollectionName
from sec_certs_page.dashboard.types.filter import FilterComponentType

DBC_GRID_COL_MAX_WIDTH = 12
"""Maximum width for a column in Dash Bootstrap Components grid system."""


class DashFilterFactory:
    """
    Factory for creating Dash components from FilterSpec objects.

    Generates Dash UI components based on FilterSpec metadata for a specific
    dataset type, ensuring UI always matches the filter registry configuration.
    """

    def __init__(self, dataset_type: CollectionName) -> None:
        """
        Initialize factory for a specific dataset type.

        :param dataset_type: Dataset type (CommonCriteria or FIPS140)
        """
        self.dataset_type = dataset_type
        self.registry = get_filter_registry(dataset_type)

    def create_filter_component(self, filter_spec: FilterSpec) -> Component:
        """
        Create a Dash component from a FilterSpec.

        :param filter_spec: Filter specification with UI metadata
        :return: Dash component (dcc or html component)
        :raises ValueError: If component type is not supported
        """
        component_type = filter_spec.component_params.component_type

        if component_type in (FilterComponentType.DROPDOWN, FilterComponentType.MULTI_DROPDOWN):
            return self._create_dropdown(filter_spec)
        elif component_type == FilterComponentType.TEXT_SEARCH:
            return self._create_text_search(filter_spec)
        elif component_type == FilterComponentType.DATE_PICKER:
            return self._create_date_picker(filter_spec)
        elif component_type == FilterComponentType.DATE_RANGE:
            return self._create_date_range(filter_spec)
        elif component_type == FilterComponentType.CHECKBOX:
            return self._create_checkbox(filter_spec)
        else:
            raise ValueError(f"Unsupported component type: {component_type}")

    @staticmethod
    def _create_dropdown(filter_spec: FilterSpec) -> dcc.Dropdown:
        """Create a Dropdown component."""
        ui = filter_spec.component_params
        return dcc.Dropdown(
            id=filter_spec.id,
            options=filter_spec.data or [],
            placeholder=ui.placeholder,
            multi=ui.multi or (ui.component_type == FilterComponentType.MULTI_DROPDOWN),
            clearable=ui.clearable,
            searchable=ui.searchable,
            value=ui.default_value,
            persistence=True,
            persistence_type="session",
        )

    @staticmethod
    def _create_text_search(filter_spec: FilterSpec) -> dcc.Input:
        """Create a text Input component for search."""
        ui = filter_spec.component_params
        return dcc.Input(
            id=filter_spec.id,
            type="text",
            placeholder=ui.placeholder,
            value=ui.default_value or "",
            debounce=False,
            persistence=True,
            persistence_type="session",
        )

    @staticmethod
    def _create_date_picker(filter_spec: FilterSpec) -> dcc.DatePickerSingle:
        """Create a DatePickerSingle component."""
        ui = filter_spec.component_params
        return dcc.DatePickerSingle(
            id=filter_spec.id,
            placeholder=ui.placeholder,
            date=ui.default_value,
            display_format="YYYY-MM-DD",
            min_date_allowed=str(ui.min_value) if ui.min_value else None,
            max_date_allowed=str(ui.max_value) if ui.max_value else None,
            persistence=True,
            persistence_type="session",
        )

    @staticmethod
    def _create_date_range(filter_spec: FilterSpec) -> dcc.DatePickerRange:
        """Create a DatePickerRange component."""
        ui = filter_spec.component_params
        return dcc.DatePickerRange(
            id=filter_spec.id,
            start_date_placeholder_text=ui.placeholder or "Start date",
            end_date_placeholder_text="End date",
            display_format="YYYY-MM-DD",
            min_date_allowed=str(ui.min_value) if ui.min_value else None,
            max_date_allowed=str(ui.max_value) if ui.max_value else None,
            persistence=True,
            persistence_type="session",
        )

    @staticmethod
    def _create_checkbox(filter_spec: FilterSpec) -> dcc.Checklist:
        """Create a Checklist component."""
        ui = filter_spec.component_params
        return dcc.Checklist(
            id=filter_spec.id,
            options=filter_spec.data or [],
            value=ui.default_value or [],
            inline=True,
        )

    def create_filter_with_label(self, filter_spec: FilterSpec) -> html.Div:
        """
        Create a filter component wrapped with label and help text.

        This is the recommended way to create filters for your dashboard.

        :param filter_spec: Filter specification
        :return: html.Div containing label, component, and help text
        """
        ui = filter_spec.component_params
        component = self.create_filter_component(filter_spec)

        children = []

        if ui.label:
            children.append(
                html.Label(
                    ui.label,
                    htmlFor=filter_spec.id,
                    style={"fontWeight": "bold", "marginBottom": "5px"},
                )
            )

        children.append(component)

        if ui.help_text:
            children.append(
                html.Small(
                    ui.help_text,
                    style={
                        "color": "#666",
                        "fontStyle": "italic",
                        "display": "block",
                        "marginTop": "3px",
                    },
                )
            )

        return html.Div(children=children, style={"marginBottom": "20px"})

    def create_all_filters(self, with_labels: bool = True) -> list[Component]:
        """
        Create all filter components for this dataset type.

        :param with_labels: Include labels and help text
        :return: List of Dash components
        """
        filter_specs = self.registry.get_all_filters()

        if with_labels:
            return [self.create_filter_with_label(spec) for spec in filter_specs.values()]
        else:
            return [self.create_filter_component(spec) for spec in filter_specs.values()]

    def create_filter_panel(self, title: str = "Filters", columns: int = 4) -> dbc.Container:
        """
        Create a complete filter panel with all filters in a Bootstrap grid.

        :param title: Panel title
        :param columns: Maximum number of filters per row
        :return: dbc.Container with all filters
        """
        filters = self.create_all_filters(with_labels=True)
        col_width = DBC_GRID_COL_MAX_WIDTH // columns

        rows = []
        for i in range(0, len(filters), columns):
            row_filters = filters[i : i + columns]
            cols = [dbc.Col(filter_comp, width=col_width) for filter_comp in row_filters]
            rows.append(dbc.Row(cols, className="mb-3"))

        return dbc.Container(
            [html.H3(title, className="mb-4"), *rows],
            fluid=True,
            className="p-4 bg-light rounded mb-4",
            id=f"{self.dataset_type.value}-filter-panel",
        )

    def get_filter_ids(self) -> list[str]:
        """Get list of filter IDs for this dataset type."""
        return list(self.registry.get_all_filters().keys())

    def create_callback_inputs(self) -> list[Any]:
        """Create list of Input() objects for all filters."""
        from dash.dependencies import Input

        filter_specs = self.registry.get_all_filters()
        inputs = []

        for filter_spec in filter_specs.values():
            if filter_spec.component_params.component_type == FilterComponentType.DATE_PICKER:
                prop = "date"
            elif filter_spec.component_params.component_type == FilterComponentType.DATE_RANGE:
                prop = "start_date"
            else:
                prop = "value"

            inputs.append(Input(filter_spec.id, prop))

        return inputs

    def collect_filter_values(self, *args) -> dict[str, Any]:
        """
        Collect filter values from callback inputs.

        Filters out None, empty strings, and empty lists.

        :param args: Filter values in same order as callback Inputs
        :return: Dictionary mapping filter IDs to non-empty values
        :raises ValueError: If number of args doesn't match number of filters
        """
        filter_specs = list(self.registry.get_all_filters().values())

        if len(args) != len(filter_specs):
            raise ValueError(f"Expected {len(filter_specs)} filter values for {self.dataset_type}, " f"got {len(args)}")

        return {
            filter_spec.id: value
            for filter_spec, value in zip(filter_specs, args)
            if value is not None and value != "" and value != []
        }
