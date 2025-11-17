"""Dash component factory for unified filter system.

This module generates Dash UI components from FilterSpec objects,
bridging the unified filter registry with the Dash framework.

Design rationale:
    - Separation: Filter specifications don't depend on Dash
    - Consistency: UI components always match filter specifications
    - Flexibility: Can customize component generation
    - Testability: Filter specifications can be tested without Dash
"""

from typing import Any

import dash_bootstrap_components as dbc
from dash import dcc, html
from dash.development.base_component import Component

from sec_certs_page.dashboard.constants import DBC_GRID_COL_MAX_WIDTH
from sec_certs_page.dashboard.filters.registry import CCFilterRegistry, FilterRegistryInterface
from sec_certs_page.dashboard.types.filters import FilterSpec, FilterUIType


class DashFilterFactory:
    """Factory for creating Dash components from FilterSpec objects.

    This class generates Dash UI components based on FilterSpec metadata,
    ensuring the UI always matches the query builder configuration.

    Design pattern: Factory Method
    """

    @staticmethod
    def create_filter_component(filter_spec: FilterSpec) -> Component:
        """Create a Dash component from a FilterSpec.

        Routes to appropriate creation method based on UI type.

        :param filter_spec: Filter specification with UI metadata
        :return: Dash component (dcc or html component)
        :raises ImportError: If Dash is not available
        :raises ValueError: If UI type is not supported
        """
        ui_type = filter_spec.ui_metadata.ui_type

        if ui_type in (FilterUIType.DROPDOWN, FilterUIType.MULTI_DROPDOWN):
            return DashFilterFactory._create_dropdown(filter_spec)
        elif ui_type == FilterUIType.TEXT_SEARCH:
            return DashFilterFactory._create_text_search(filter_spec)
        elif ui_type == FilterUIType.DATE_PICKER:
            return DashFilterFactory._create_date_picker(filter_spec)
        elif ui_type == FilterUIType.DATE_RANGE:
            return DashFilterFactory._create_date_range(filter_spec)
        elif ui_type == FilterUIType.RANGE_SLIDER:
            return DashFilterFactory._create_range_slider(filter_spec)
        elif ui_type == FilterUIType.CHECKBOX:
            return DashFilterFactory._create_checkbox(filter_spec)
        else:
            raise ValueError(f"Unsupported UI type: {ui_type}")

    @staticmethod
    def _create_dropdown(filter_spec: FilterSpec) -> dcc.Dropdown:
        """Create a Dropdown component.

        :param filter_spec: Filter specification
        :return: dcc.Dropdown component
        """
        ui = filter_spec.ui_metadata

        return dcc.Dropdown(
            id=filter_spec.id,
            options=ui.options or [],
            placeholder=ui.placeholder,
            multi=ui.multi or (ui.ui_type == FilterUIType.MULTI_DROPDOWN),
            clearable=ui.clearable,
            searchable=ui.searchable,
            value=ui.default_value,
            persistence=True,  # Persist across page refreshes
            persistence_type="session",
        )

    @staticmethod
    def _create_text_search(filter_spec: FilterSpec) -> dcc.Input:
        """Create a text Input component for search.

        :param filter_spec: Filter specification
        :return: dcc.Input component
        """
        ui = filter_spec.ui_metadata

        return dcc.Input(
            id=filter_spec.id,
            type="text",
            placeholder=ui.placeholder,
            value=ui.default_value or "",
            debounce=False,  # Wait for user to stop typing
            persistence=True,
            persistence_type="session",
        )

    @staticmethod
    def _create_date_picker(filter_spec: FilterSpec) -> dcc.DatePickerSingle:
        """Create a DatePickerSingle component.

        :param filter_spec: Filter specification
        :return: dcc.DatePickerSingle component
        """
        ui = filter_spec.ui_metadata

        return dcc.DatePickerSingle(
            id=filter_spec.id,
            placeholder=ui.placeholder,
            date=ui.default_value,
            display_format="YYYY-MM-DD",
            min_date_allowed=str(ui.min_value),
            max_date_allowed=str(ui.max_value),
            persistence=True,
            persistence_type="session",
        )

    @staticmethod
    def _create_date_range(filter_spec: FilterSpec) -> dcc.DatePickerRange:
        """Create a DatePickerRange component.

        :param filter_spec: Filter specification
        :return: dcc.DatePickerRange component
        """
        ui = filter_spec.ui_metadata

        return dcc.DatePickerRange(
            id=filter_spec.id,
            start_date_placeholder_text=ui.placeholder or "Start date",
            end_date_placeholder_text="End date",
            display_format="YYYY-MM-DD",
            min_date_allowed=str(ui.min_value),
            max_date_allowed=str(ui.max_value),
            persistence=True,
            persistence_type="session",
        )

    @staticmethod
    def _create_range_slider(filter_spec: FilterSpec) -> dcc.RangeSlider:
        """Create a RangeSlider component.

        :param filter_spec: Filter specification
        :return: dcc.RangeSlider component
        """
        ui = filter_spec.ui_metadata

        # Ensure min/max values are provided
        if ui.min_value is None or ui.max_value is None:
            raise ValueError(f"RangeSlider '{filter_spec.id}' requires min_value and max_value")

        # Ensures marks keys match the slider's numeric type
        try:
            if filter_spec.data_type == int:
                min_val = int(ui.min_value)
                max_val = int(ui.max_value)
            else:
                min_val = float(ui.min_value)
                max_val = float(ui.max_value)
        except (ValueError, TypeError) as e:
            raise TypeError(
                f"RangeSlider '{filter_spec.id}' requires numeric min_value and max_value, "
                f"but conversion failed: {e}"
            ) from e

        return dcc.RangeSlider(
            id=filter_spec.id,
            min=min_val,
            max=max_val,
            value=ui.default_value or [min_val, max_val],
            marks={
                min_val: str(min_val),
                max_val: str(max_val),
            },
            tooltip={"placement": "bottom", "always_visible": True},
        )

    @staticmethod
    def _create_checkbox(filter_spec: FilterSpec) -> dcc.Checklist:
        """Create a Checklist component.

        :param filter_spec: Filter specification
        :return: dcc.Checklist component
        """
        ui = filter_spec.ui_metadata

        return dcc.Checklist(
            id=filter_spec.id,
            options=ui.options or [],
            value=ui.default_value or [],
            inline=True,
        )

    @staticmethod
    def create_filter_with_label(filter_spec: FilterSpec) -> html.Div:
        """Create a filter component wrapped with label and help text.

        This is the recommended way to create filters for your dashboard,
        as it includes proper labeling and help text.

        :param filter_spec: Filter specification
        :return: html.Div containing label, component, and help text
        """
        ui = filter_spec.ui_metadata
        component = DashFilterFactory.create_filter_component(filter_spec)

        children = []

        # Add label
        if ui.label:
            children.append(
                html.Label(ui.label, htmlFor=filter_spec.id, style={"fontWeight": "bold", "marginBottom": "5px"})
            )

        # Add component
        children.append(component)

        # Add help text
        if ui.help_text:
            children.append(
                html.Small(
                    ui.help_text, style={"color": "#666", "fontStyle": "italic", "display": "block", "marginTop": "3px"}
                )
            )

        return html.Div(children=children, style={"marginBottom": "20px"})

    @staticmethod
    def create_all_filters(with_labels: bool = True) -> list[Component]:
        """Create all filter components for a dataset.

        Convenience method to generate all filters at once.

        :param dataset_type: Dataset type ('cc' or 'fips')
        :param with_labels: Include labels and help text
        :return: List of Dash components
        """
        filter_specs = CCFilterRegistry.get_all_filters()

        if with_labels:
            return [DashFilterFactory.create_filter_with_label(filter_def) for filter_def in filter_specs.values()]
        else:
            return [DashFilterFactory.create_filter_component(filter_def) for filter_def in filter_specs.values()]

    @staticmethod
    def create_filter_panel(title: str = "Filters", columns: int = 4) -> dbc.Container:
        """Create a complete filter panel with all filters.

        This creates a ready-to-use filter panel that can be dropped
        into your dashboard layout. Filters are displayed in a responsive
        Bootstrap grid with up to `columns` filters per row.

        :param title: Panel title
        :param columns: Maximum number of filters per row (default: 4)
        :return: dbc.Container containing all filters in a Bootstrap grid layout
        """
        filters = DashFilterFactory.create_all_filters(with_labels=True)

        # Calculate column width (Bootstrap uses 12-column grid)
        col_width = DBC_GRID_COL_MAX_WIDTH // columns

        rows = []
        for i in range(0, len(filters), columns):
            row_filters = filters[i : i + columns]
            cols = [dbc.Col(filter_comp, width=col_width) for filter_comp in row_filters]
            rows.append(dbc.Row(cols, className="mb-3"))

        return dbc.Container(
            [
                html.H3(title, className="mb-4"),
                *rows,
            ],
            fluid=True,
            className="p-4 bg-light rounded mb-4",
            id="filter-panel",
        )


class DashCallbackHelper:
    """Helper utilities for Dash callbacks with unified filters.

    Provides convenience methods for working with filter values in callbacks.
    """

    @staticmethod
    def collect_filter_values(*args, filter_registry: FilterRegistryInterface) -> dict[str, Any]:
        """Collect filter values from callback inputs.

        Usage in callback:
            @app.callback(
                Output('chart', 'figure'),
                Input('category-filter', 'value'),
                Input('scheme-filter', 'value'),
                Input('not-valid-before-filter', 'date'),
            )
            def update_chart(category, scheme, date_from):
                filters = DashCallbackHelper.collect_filter_values(
                    category, scheme, date_from,
                    dataset_type='cc'
                )
                df = data_service.get_cc_dataframe(filters)
                return create_figure(df)

        :param args: Filter values in same order as callback Inputs
        :param dataset_type: Dataset type
        :return: Dictionary mapping filter IDs to values
        """
        filter_specs = list(filter_registry.get_all_filters().values())

        if len(args) != len(filter_specs):
            raise ValueError(f"Expected {len(filter_specs)} filter values, got {len(args)}")

        return {
            filter_def.id: value
            for filter_def, value in zip(filter_specs, args)
            if value is not None and value != "" and value != []
        }

    @staticmethod
    def get_filter_ids() -> list[str]:
        """Get list of filter IDs in consistent order.

        Useful for defining callback Inputs in correct order.

        :param dataset_type: Dataset type
        :return: List of filter IDs
        """
        return list(CCFilterRegistry.get_all_filters().keys())

    @staticmethod
    def create_callback_inputs() -> list[Any]:
        """
        Create list of Input() objects for all filters.

        Note:
            ```
                from dash.dependencies import Output

                @app.callback(
                    Output('chart', 'figure'),
                    DashCallbackHelper.create_callback_inputs('cc')
                )
                def update_chart(*filter_values):
                    filters = DashCallbackHelper.collect_filter_values(
                        *filter_values,
                        dataset_type='cc'
                    )
            ```

        :param dataset_type: Dataset type
        :return: List of Input objects
        """

        from dash.dependencies import Input

        filter_specs = CCFilterRegistry.get_all_filters()

        inputs = []
        for filter_def in filter_specs.values():
            # Determine property based on UI type
            if filter_def.ui_metadata.ui_type in (FilterUIType.DATE_PICKER, FilterUIType.DATE_RANGE):
                prop = "date"
            elif filter_def.ui_metadata.ui_type == FilterUIType.RANGE_SLIDER:
                prop = "value"
            else:
                prop = "value"

            inputs.append(Input(filter_def.id, prop))

        return inputs
