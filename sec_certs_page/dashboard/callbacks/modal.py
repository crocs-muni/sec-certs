import logging
from datetime import date
from typing import TYPE_CHECKING
from uuid import uuid4

import dash_bootstrap_components as dbc
from dash import ALL, MATCH, ctx, dcc, html, no_update
from dash.dependencies import Input, Output, State
from dash.development.base_component import Component

from ..chart.chart import AxisConfig, ChartConfig, generate_custom_chart_name
from ..dependencies import ComponentID, ComponentIDBuilder, PatternMatchingComponentID
from ..filters.query_builder import build_chart_pipeline
from ..types.aggregations import get_aggregations_for_type
from ..types.chart import AvailableChartTypes
from ..types.common import CollectionName
from ..types.filter import AggregationType

if TYPE_CHECKING:
    from ..base import Dash
    from ..chart.registry import ChartRegistry
    from ..data import DataService

logger = logging.getLogger(__name__)


def register_modal_callbacks(
    dash_app: "Dash",
    collection_name: CollectionName,
    data_service: "DataService",
    chart_registry: "ChartRegistry",
) -> None:
    _register_modal_toggle(dash_app, collection_name)
    _register_modal_filter_reset(dash_app, collection_name)
    _register_modal_mode(dash_app, collection_name)
    _register_edit_handler(dash_app, collection_name, chart_registry)
    _register_modal_filter_ui(dash_app, collection_name)
    _register_modal_filter_options(dash_app, collection_name, data_service)
    _register_filter_actions(dash_app, collection_name)
    _register_axis_options(dash_app, collection_name)
    _register_aggregation_options(dash_app, collection_name)
    _register_y_field_state(dash_app, collection_name)
    _register_x_label_autofill(dash_app, collection_name)
    _register_chart_type_help(dash_app, collection_name)
    _register_color_by_toggle(dash_app, collection_name)
    _register_chart_creation(dash_app, collection_name, data_service, chart_registry)


def _register_modal_toggle(dash_app: "Dash", collection_name: CollectionName) -> None:
    """Handle modal open/close and reset form when opening in create mode.

    This is the single source of truth for create mode - it resets all form fields.
    Edit mode is handled separately by _register_edit_handler.

    Note: Modal filter values are NOT reset here because that would require ALL pattern
    which conflicts with MATCH pattern used in filter action callbacks (clear/select all).
    Filters are reset via _register_modal_filter_reset which uses a compatible approach.
    """
    component_id = ComponentIDBuilder(collection_name)

    @dash_app.callback(
        output=dict(
            is_open=Output(component_id(ComponentID.CREATE_CHART_MODAL), "is_open"),
            edit_id=Output(component_id(ComponentID.EDIT_CHART_ID), "data"),
            # Form fields - reset on create, no_update on close
            title=Output(component_id(ComponentID.MODAL_CHART_TITLE), "value"),
            chart_type=Output(component_id(ComponentID.MODAL_CHART_TYPE), "value"),
            x_field=Output(component_id(ComponentID.MODAL_X_FIELD), "value"),
            x_label=Output(component_id(ComponentID.MODAL_X_LABEL), "value"),
            color_field=Output(component_id(ComponentID.MODAL_COLOR_FIELD), "value"),
            aggregation=Output(component_id(ComponentID.MODAL_AGGREGATION), "value"),
            y_field=Output(component_id(ComponentID.MODAL_Y_FIELD), "value"),
            y_label=Output(component_id(ComponentID.MODAL_Y_LABEL), "value"),
            show_legend=Output(component_id(ComponentID.MODAL_SHOW_LEGEND), "value"),
            show_grid=Output(component_id(ComponentID.MODAL_SHOW_GRID), "value"),
            color_by_open=Output(component_id(ComponentID.COLOR_BY_COLLAPSE), "is_open"),
        ),
        inputs=dict(
            open_clicks=Input(component_id(ComponentID.OPEN_CREATE_CHART_MODAL_BTN), "n_clicks"),
            cancel_clicks=Input(component_id(ComponentID.MODAL_CANCEL_BTN), "n_clicks"),
        ),
        state=dict(
            is_open=State(component_id(ComponentID.CREATE_CHART_MODAL), "is_open"),
        ),
        prevent_initial_call=True,
    )
    def toggle_modal(open_clicks, cancel_clicks, is_open):
        triggered = ctx.triggered_id
        open_btn_id = component_id(ComponentID.OPEN_CREATE_CHART_MODAL_BTN)
        cancel_btn_id = component_id(ComponentID.MODAL_CANCEL_BTN)

        no_change_form = dict(
            title=no_update,
            chart_type=no_update,
            x_field=no_update,
            x_label=no_update,
            color_field=no_update,
            aggregation=no_update,
            y_field=no_update,
            y_label=no_update,
            show_legend=no_update,
            show_grid=no_update,
            color_by_open=no_update,
        )

        if triggered == open_btn_id:
            # Opening in CREATE mode - reset all form fields
            return dict(
                is_open=True,
                edit_id=None,
                title="",
                chart_type="bar",
                x_field=None,
                x_label="",
                color_field=None,
                aggregation="count",
                y_field=None,
                y_label="",
                show_legend=True,
                show_grid=True,
                color_by_open=False,
            )

        if triggered == cancel_btn_id:
            # Closing modal - don't change form values
            return dict(is_open=False, edit_id=None, **no_change_form)

        return dict(is_open=is_open, edit_id=no_update, **no_change_form)


def _register_modal_filter_reset(dash_app: "Dash", collection_name: CollectionName) -> None:
    """Reset modal filter values when opening in create mode.

    This is separate from _register_modal_toggle to avoid mixing ALL and MATCH
    wildcard patterns on the same output (which Dash doesn't allow).
    """
    component_id = ComponentIDBuilder(collection_name)
    pattern_id = PatternMatchingComponentID(collection_name)

    @dash_app.callback(
        output=dict(
            filter_values=Output(pattern_id(ComponentID.MODAL_FILTER, ALL, use_prefix=True, index_key="field"), "value")
        ),
        inputs=dict(
            open_clicks=Input(component_id(ComponentID.OPEN_CREATE_CHART_MODAL_BTN), "n_clicks"),
        ),
        state=dict(
            current_filter_values=State(
                pattern_id(ComponentID.MODAL_FILTER, ALL, use_prefix=True, index_key="field"), "value"
            ),
        ),
        prevent_initial_call=True,
    )
    def reset_modal_filters(open_clicks, current_filter_values):
        """Reset all modal filter values when Add Chart button is clicked."""
        if open_clicks:
            return dict(filter_values=[None] * len(current_filter_values))
        return dict(filter_values=[no_update] * len(current_filter_values))


def _register_modal_mode(dash_app: "Dash", collection_name: CollectionName) -> None:
    component_id = ComponentIDBuilder(collection_name)

    @dash_app.callback(
        output=dict(
            title=Output(component_id(ComponentID.MODAL_TITLE), "children"),
            btn_text=Output(component_id(ComponentID.MODAL_CREATE_BTN), "children"),
        ),
        inputs=dict(edit_chart_id=Input(component_id(ComponentID.EDIT_CHART_ID), "data")),
        prevent_initial_call=True,
    )
    def update_modal_mode(edit_chart_id):
        """Update modal title/button based on edit mode - only when edit_id changes."""
        if edit_chart_id:
            return dict(
                title=[html.I(className="fas fa-edit me-2"), "Edit Chart"],
                btn_text=[html.I(className="fas fa-save me-2"), "Save Changes"],
            )
        return dict(
            title=[html.I(className="fas fa-chart-bar me-2"), "Create Custom Chart"],
            btn_text=[html.I(className="fas fa-plus me-2"), "Create Chart"],
        )


def _register_edit_handler(
    dash_app: "Dash",
    collection_name: CollectionName,
    chart_registry: "ChartRegistry",
) -> None:
    component_id = ComponentIDBuilder(collection_name)
    pattern_id = PatternMatchingComponentID(collection_name=None)

    @dash_app.callback(
        output=dict(
            is_open=Output(component_id(ComponentID.CREATE_CHART_MODAL), "is_open", allow_duplicate=True),
            edit_id=Output(component_id(ComponentID.EDIT_CHART_ID), "data", allow_duplicate=True),
            title=Output(component_id(ComponentID.MODAL_CHART_TITLE), "value", allow_duplicate=True),
            chart_type=Output(component_id(ComponentID.MODAL_CHART_TYPE), "value", allow_duplicate=True),
            x_field=Output(component_id(ComponentID.MODAL_X_FIELD), "value", allow_duplicate=True),
            x_label=Output(component_id(ComponentID.MODAL_X_LABEL), "value", allow_duplicate=True),
            color_field=Output(component_id(ComponentID.MODAL_COLOR_FIELD), "value", allow_duplicate=True),
            aggregation=Output(component_id(ComponentID.MODAL_AGGREGATION), "value", allow_duplicate=True),
            y_field=Output(component_id(ComponentID.MODAL_Y_FIELD), "value", allow_duplicate=True),
            y_label=Output(component_id(ComponentID.MODAL_Y_LABEL), "value", allow_duplicate=True),
            show_legend=Output(component_id(ComponentID.MODAL_SHOW_LEGEND), "value", allow_duplicate=True),
            show_grid=Output(component_id(ComponentID.MODAL_SHOW_GRID), "value", allow_duplicate=True),
            color_by_open=Output(component_id(ComponentID.COLOR_BY_COLLAPSE), "is_open", allow_duplicate=True),
        ),
        inputs=dict(n_clicks_list=Input(pattern_id(ComponentID.CHART_EDIT, ALL), "n_clicks")),
        state=dict(
            id_list=State(pattern_id(ComponentID.CHART_EDIT, ALL), "id"),
            chart_configs=State(component_id(ComponentID.CHART_CONFIGS_STORE), "data"),
        ),
        prevent_initial_call=True,
    )
    def handle_edit_button(n_clicks_list, id_list, chart_configs):
        no_change = dict(
            is_open=no_update,
            edit_id=no_update,
            title=no_update,
            chart_type=no_update,
            x_field=no_update,
            x_label=no_update,
            color_field=no_update,
            aggregation=no_update,
            y_field=no_update,
            y_label=no_update,
            show_legend=no_update,
            show_grid=no_update,
            color_by_open=no_update,
        )

        if not n_clicks_list or not any(n_clicks_list):
            return no_change

        for i, n_clicks in enumerate(n_clicks_list):
            if n_clicks:
                chart_id = id_list[i]["index"]
                config_dict = (chart_configs or {}).get(chart_id)

                if not config_dict:
                    chart_instance = chart_registry.get(chart_id)
                    if chart_instance:
                        config_dict = chart_instance.config.to_dict()

                if not config_dict:
                    return no_change

                x_axis = config_dict.get("x_axis", {})
                y_axis = config_dict.get("y_axis", {})
                color_axis = config_dict.get("color_axis")

                return dict(
                    is_open=True,
                    edit_id=chart_id,
                    title=config_dict.get("title", ""),
                    chart_type=config_dict.get("chart_type"),
                    x_field=x_axis.get("field") if x_axis else None,
                    x_label=x_axis.get("label", "") if x_axis else "",
                    color_field=color_axis.get("field") if color_axis else None,
                    aggregation=y_axis.get("aggregation", "count") if y_axis else "count",
                    y_field=y_axis.get("field") if y_axis and y_axis.get("field") != "count" else None,
                    y_label=y_axis.get("label", "") if y_axis else "",
                    show_legend=config_dict.get("show_legend", True),
                    show_grid=config_dict.get("show_grid", True),
                    color_by_open=color_axis is not None,
                )

        return no_change


def _register_modal_filter_ui(dash_app: "Dash", collection_name: CollectionName) -> None:
    component_id = ComponentIDBuilder(collection_name)

    @dash_app.callback(
        output=dict(
            children=Output(component_id(ComponentID.MODAL_FILTERS_CONTAINER), "children"),
            filters_ready=Output(component_id(ComponentID.MODAL_FILTERS_READY), "data"),
        ),
        inputs=dict(filter_specs=Input(component_id(ComponentID.FILTER_SPECS), "data")),
        state=dict(current_ready=State(component_id(ComponentID.MODAL_FILTERS_READY), "data")),
        prevent_initial_call=True,
    )
    def generate_modal_filter_ui(filter_specs, current_ready):
        """Generate modal filter UI - only when filter_specs are loaded (modal open)."""
        if not filter_specs:
            return dict(
                children=html.P("No filters available.", className="text-muted"),
                filters_ready=no_update,
            )

        filter_rows = []
        pattern_id = PatternMatchingComponentID(collection_name)
        for i in range(0, len(filter_specs), 2):
            cols = []
            for spec in filter_specs[i : i + 2]:
                component_type = spec.get("component_type", "dropdown")
                field_id = pattern_id(ComponentID.MODAL_FILTER, spec["id"], use_prefix=True, index_key="field")
                filter_component = _create_filter_component(collection_name, spec, field_id)

                children = [filter_component]
                if component_type != "checkbox":
                    children.insert(0, html.Div(spec["label"], className="fw-bold small mb-1"))
                if spec.get("help_text"):
                    children.append(html.Small(spec["help_text"], className="text-muted"))

                cols.append(dbc.Col(width=12, md=6, children=children, className="mb-2"))

            filter_rows.append(dbc.Row(cols, className="g-2"))

        # Increment filters_ready to signal that UI is ready for options population
        return dict(children=filter_rows, filters_ready=(current_ready or 0) + 1)


def _create_filter_component(collection_name: CollectionName, spec: dict, field_id: dict | str) -> Component:
    component_type = spec.get("component_type", "dropdown")
    placeholder = spec.get("placeholder") or f"Select {spec['label']}..."

    if component_type == "text_search":
        return html.Div(
            className="d-flex gap-2 align-items-center",
            children=[
                dbc.Input(
                    id=field_id,
                    type="text",
                    placeholder=spec.get("placeholder") or f"Search {spec['label']}...",
                    className="flex-grow-1",
                ),
                _create_clear_button(collection_name, spec["id"]),
            ],
        )

    if component_type == "date_picker":
        return html.Div(
            className="d-flex gap-2 align-items-center",
            children=[
                html.Div(
                    className="date-picker-wrapper flex-grow-1",
                    children=[
                        html.I(className="fas fa-calendar-alt date-picker-icon"),
                        dcc.DatePickerSingle(
                            id=field_id,
                            placeholder=spec.get("placeholder") or "YYYY-MM-DD",
                            display_format="YYYY-MM-DD",
                            className="dash-bootstrap",
                            show_outside_days=True,
                            stay_open_on_select=True,
                            number_of_months_shown=2,
                            with_portal=False,
                            first_day_of_week=1,
                            min_date_allowed="1990-01-01",
                            max_date_allowed="2030-12-31",
                            initial_visible_month=date.today().isoformat(),
                        ),
                    ],
                ),
                _create_clear_button(collection_name, spec["id"]),
            ],
        )

    if component_type == "date_range":
        return html.Div(
            className="d-flex gap-2 align-items-center",
            children=[
                html.Div(
                    className="date-picker-wrapper date-range-wrapper flex-grow-1",
                    children=[
                        html.I(className="fas fa-calendar-alt date-picker-icon"),
                        dcc.DatePickerRange(
                            id=field_id,
                            display_format="YYYY-MM-DD",
                            className="dash-bootstrap",
                            show_outside_days=True,
                            number_of_months_shown=1,
                            with_portal=False,
                            first_day_of_week=1,
                            min_date_allowed="1990-01-01",
                            max_date_allowed="2030-12-31",
                            initial_visible_month=date.today().isoformat(),
                        ),
                    ],
                ),
                _create_clear_button(collection_name, spec["field"]),
            ],
        )

    if component_type == "checkbox":
        return dbc.Checkbox(id=field_id, label=spec["label"])

    if component_type == "multi_dropdown":
        pattern_id = PatternMatchingComponentID(collection_name)
        return html.Div(
            children=[
                dcc.Dropdown(
                    id=field_id,
                    options=[],
                    placeholder=placeholder,
                    multi=True,
                    clearable=True,
                    className="dash-bootstrap",
                ),
                html.Div(
                    className="mt-1 d-flex gap-1",
                    children=[
                        dbc.Button(
                            "Select All",
                            id=pattern_id(
                                ComponentID.SELECT_ALL_FILTER, spec["id"], use_prefix=True, index_key="field"
                            ),
                            color="link",
                            size="sm",
                            className="p-0 text-decoration-none",
                        ),
                        html.Span("·", className="text-muted"),
                        dbc.Button(
                            "Clear",
                            id=pattern_id(ComponentID.CLEAR_FILTER, spec["id"], use_prefix=True, index_key="field"),
                            color="link",
                            size="sm",
                            className="p-0 text-decoration-none",
                        ),
                    ],
                ),
            ],
        )

    return dcc.Dropdown(
        id=field_id,
        options=[],
        placeholder=placeholder,
        multi=False,
        clearable=True,
        className="dash-bootstrap",
    )


def _create_clear_button(collection_name: CollectionName, field_id: str) -> dbc.Button:
    pattern_id = PatternMatchingComponentID(collection_name)
    return dbc.Button(
        html.I(className="fas fa-times"),
        id=pattern_id(ComponentID.CLEAR_FILTER, field_id, use_prefix=True, index_key="field"),
        color="secondary",
        outline=True,
        size="sm",
        className="px-2",
        title="Clear",
    )


def _register_modal_filter_options(
    dash_app: "Dash",
    collection_name: CollectionName,
    data_service: "DataService",
) -> None:
    component_id = ComponentIDBuilder(collection_name)
    pattern_id = PatternMatchingComponentID(collection_name)

    @dash_app.callback(
        output=dict(
            options=Output(pattern_id(ComponentID.MODAL_FILTER, ALL, use_prefix=True, index_key="field"), "options")
        ),
        inputs=dict(filters_ready=Input(component_id(ComponentID.MODAL_FILTERS_READY), "data")),
        state=dict(filter_specs=State(component_id(ComponentID.FILTER_SPECS), "data")),
        prevent_initial_call=True,
    )
    def populate_modal_filter_options(filters_ready, filter_specs):
        """Populate modal filter options - only after filter UI components are rendered."""
        if not filters_ready or not filter_specs:
            return dict(options=[])

        options_list = []
        for spec in filter_specs:
            field = spec["field"]
            operator = spec.get("operator", "")
            component_type = spec.get("component_type", "dropdown")

            if component_type not in ("dropdown", "multi_dropdown"):
                options_list.append([])
                continue

            try:
                if operator == "$year_in":
                    unique_values = data_service.get_unique_values(collection_name, "year_from")
                else:
                    unique_values = data_service.get_unique_values(collection_name, field)

                options = [{"label": str(v), "value": v} for v in unique_values if v is not None]

                if component_type == "dropdown" and options:
                    options.insert(0, {"label": "── Not selected ──", "value": "__all__"})

                options_list.append(options)
            except Exception:
                options_list.append([])

        return dict(options=options_list)


def _register_filter_actions(dash_app: "Dash", collection_name: CollectionName) -> None:
    pattern_id = PatternMatchingComponentID(collection_name)

    @dash_app.callback(
        output=dict(
            value=Output(
                pattern_id(ComponentID.MODAL_FILTER, MATCH, use_prefix=True, index_key="field"),
                "value",
                allow_duplicate=True,
            )
        ),
        inputs=dict(
            n_clicks=Input(pattern_id(ComponentID.CLEAR_FILTER, MATCH, use_prefix=True, index_key="field"), "n_clicks")
        ),
        prevent_initial_call=True,
    )
    def clear_filter_value(n_clicks):
        if n_clicks:
            return dict(value=None)
        return dict(value=no_update)

    @dash_app.callback(
        output=dict(
            value=Output(
                pattern_id(ComponentID.MODAL_FILTER, MATCH, use_prefix=True, index_key="field"),
                "value",
                allow_duplicate=True,
            )
        ),
        inputs=dict(
            n_clicks=Input(
                pattern_id(ComponentID.SELECT_ALL_FILTER, MATCH, use_prefix=True, index_key="field"), "n_clicks"
            )
        ),
        state=dict(
            options=State(pattern_id(ComponentID.MODAL_FILTER, MATCH, use_prefix=True, index_key="field"), "options")
        ),
        prevent_initial_call=True,
    )
    def select_all_filter_values(n_clicks, options):
        if n_clicks and options:
            return dict(value=[opt["value"] for opt in options if opt.get("value") != "__all__"])
        return dict(value=no_update)


def _register_axis_options(dash_app: "Dash", collection_name: CollectionName) -> None:
    component_id = ComponentIDBuilder(collection_name)

    @dash_app.callback(
        output=dict(
            x_options=Output(component_id(ComponentID.MODAL_X_FIELD), "options"),
            color_options=Output(component_id(ComponentID.MODAL_COLOR_FIELD), "options"),
        ),
        inputs=dict(available_fields=Input(component_id(ComponentID.AVAILABLE_FIELDS), "data")),
        prevent_initial_call=True,
    )
    def populate_axis_field_options(available_fields):
        """Populate axis field options - only when available_fields are loaded (modal open)."""
        if not available_fields:
            return dict(x_options=[], color_options=[])
        options = [{"label": f["label"], "value": f["value"]} for f in available_fields]
        return dict(x_options=options, color_options=options)


def _register_aggregation_options(dash_app: "Dash", collection_name: CollectionName) -> None:
    component_id = ComponentIDBuilder(collection_name)

    @dash_app.callback(
        output=dict(options=Output(component_id(ComponentID.MODAL_AGGREGATION), "options")),
        inputs=dict(x_field_value=Input(component_id(ComponentID.MODAL_X_FIELD), "value")),
        state=dict(available_fields=State(component_id(ComponentID.AVAILABLE_FIELDS), "data")),
        prevent_initial_call=True,
    )
    def update_aggregation_options(x_field_value, available_fields):
        default = [{"label": agg.value.upper(), "value": agg.value} for agg in AggregationType]
        if not x_field_value or not available_fields:
            return dict(options=default)

        field_info = next((f for f in available_fields if f["value"] == x_field_value), None)
        if field_info:
            return dict(options=get_aggregations_for_type(field_info["data_type"]))

        return dict(options=default)


def _register_y_field_state(dash_app: "Dash", collection_name: CollectionName) -> None:
    component_id = ComponentIDBuilder(collection_name)

    @dash_app.callback(
        output=dict(
            disabled=Output(component_id(ComponentID.MODAL_Y_FIELD), "disabled"),
            options=Output(component_id(ComponentID.MODAL_Y_FIELD), "options"),
            help_text=Output(component_id(ComponentID.MODAL_Y_FIELD_HELP), "children"),
        ),
        inputs=dict(aggregation_value=Input(component_id(ComponentID.MODAL_AGGREGATION), "value")),
        state=dict(available_fields=State(component_id(ComponentID.AVAILABLE_FIELDS), "data")),
        prevent_initial_call=True,
    )
    def update_y_field_state(aggregation_value, available_fields):
        """Update Y-field state based on aggregation - only when aggregation changes."""
        if aggregation_value == AggregationType.COUNT.value:
            return dict(disabled=True, options=[], help_text="Not required for COUNT aggregation.")

        numeric_types = {"int", "float", "number", "numeric"}
        numeric_fields = []
        if available_fields:
            numeric_fields = [
                {"label": f["label"], "value": f["value"]}
                for f in available_fields
                if f["data_type"].lower() in numeric_types
            ]

        help_text = "Select a numeric field to aggregate."
        if not numeric_fields:
            help_text = "No numeric fields available for aggregation."

        return dict(disabled=False, options=numeric_fields, help_text=help_text)


def _register_x_label_autofill(dash_app: "Dash", collection_name: CollectionName) -> None:
    component_id = ComponentIDBuilder(collection_name)

    @dash_app.callback(
        output=dict(value=Output(component_id(ComponentID.MODAL_X_LABEL), "value", allow_duplicate=True)),
        inputs=dict(x_field_value=Input(component_id(ComponentID.MODAL_X_FIELD), "value")),
        state=dict(
            available_fields=State(component_id(ComponentID.AVAILABLE_FIELDS), "data"),
            current_label=State(component_id(ComponentID.MODAL_X_LABEL), "value"),
        ),
        prevent_initial_call=True,
    )
    def auto_fill_x_label(x_field_value, available_fields, current_label):
        if current_label:
            return dict(value=no_update)

        if x_field_value and available_fields:
            field_info = next((f for f in available_fields if f["value"] == x_field_value), None)
            if field_info:
                return dict(value=field_info["label"])

        return dict(value="")


def _register_chart_type_help(dash_app: "Dash", collection_name: CollectionName) -> None:
    component_id = ComponentIDBuilder(collection_name)

    @dash_app.callback(
        output=dict(children=Output(component_id(ComponentID.CHART_TYPE_HELP), "children")),
        inputs=dict(chart_type=Input(component_id(ComponentID.MODAL_CHART_TYPE), "value")),
        prevent_initial_call=True,
    )
    def show_chart_type_help(chart_type):
        """Show chart type specific help - only when chart type changes."""
        if chart_type == "stacked_bar":
            return dict(
                children=dbc.Alert(
                    [
                        html.I(className="fas fa-info-circle me-2"),
                        "Stacked Bar requires a ",
                        html.Strong("Color By"),
                        " field to stack values. Expand 'Secondary Grouping' below.",
                    ],
                    color="info",
                    className="mb-0 py-2 small",
                )
            )
        return dict(children=None)


def _register_color_by_toggle(dash_app: "Dash", collection_name: CollectionName) -> None:
    component_id = ComponentIDBuilder(collection_name)

    @dash_app.callback(
        output=dict(
            is_open=Output(component_id(ComponentID.COLOR_BY_COLLAPSE), "is_open", allow_duplicate=True),
            icon_class=Output(component_id(ComponentID.COLOR_BY_ICON), "className"),
        ),
        inputs=dict(n_clicks=Input(component_id(ComponentID.COLOR_BY_TOGGLE), "n_clicks")),
        state=dict(is_open=State(component_id(ComponentID.COLOR_BY_COLLAPSE), "is_open")),
        prevent_initial_call=True,
    )
    def toggle_color_by_section(n_clicks, is_open):
        if n_clicks:
            new_state = not is_open
            icon_class = "fas fa-chevron-down me-2" if new_state else "fas fa-chevron-right me-2"
            return dict(is_open=new_state, icon_class=icon_class)
        return dict(is_open=is_open, icon_class="fas fa-chevron-right me-2")


def _register_chart_creation(
    dash_app: "Dash",
    collection_name: CollectionName,
    data_service: "DataService",
    chart_registry: "ChartRegistry",
) -> None:
    component_id = ComponentIDBuilder(collection_name)
    pattern_id = PatternMatchingComponentID(collection_name)

    @dash_app.callback(
        output=dict(
            modal_open=Output(component_id(ComponentID.CREATE_CHART_MODAL), "is_open", allow_duplicate=True),
            alert_open=Output(component_id(ComponentID.MODAL_VALIDATION_ALERT), "is_open"),
            alert_children=Output(component_id(ComponentID.MODAL_VALIDATION_ALERT), "children"),
            edit_id=Output(component_id(ComponentID.EDIT_CHART_ID), "data", allow_duplicate=True),
            render_trigger=Output(component_id(ComponentID.RENDER_TRIGGER), "data", allow_duplicate=True),
            chart_configs=Output(component_id(ComponentID.CHART_CONFIGS_STORE), "data", allow_duplicate=True),
        ),
        inputs=dict(n_clicks=Input(component_id(ComponentID.MODAL_CREATE_BTN), "n_clicks")),
        state=dict(
            title=State(component_id(ComponentID.MODAL_CHART_TITLE), "value"),
            chart_type=State(component_id(ComponentID.MODAL_CHART_TYPE), "value"),
            x_field=State(component_id(ComponentID.MODAL_X_FIELD), "value"),
            x_label=State(component_id(ComponentID.MODAL_X_LABEL), "value"),
            color_field=State(component_id(ComponentID.MODAL_COLOR_FIELD), "value"),
            aggregation=State(component_id(ComponentID.MODAL_AGGREGATION), "value"),
            y_field=State(component_id(ComponentID.MODAL_Y_FIELD), "value"),
            y_label=State(component_id(ComponentID.MODAL_Y_LABEL), "value"),
            show_legend=State(component_id(ComponentID.MODAL_SHOW_LEGEND), "value"),
            show_grid=State(component_id(ComponentID.MODAL_SHOW_GRID), "value"),
            current_filter_values=State(component_id(ComponentID.FILTER_STORE), "data"),
            modal_filter_values=State(
                pattern_id(ComponentID.MODAL_FILTER, ALL, use_prefix=True, index_key="field"), "value"
            ),
            filter_specs=State(component_id(ComponentID.FILTER_SPECS), "data"),
            edit_chart_id=State(component_id(ComponentID.EDIT_CHART_ID), "data"),
            render_trigger=State(component_id(ComponentID.RENDER_TRIGGER), "data"),
            chart_configs=State(component_id(ComponentID.CHART_CONFIGS_STORE), "data"),
        ),
        prevent_initial_call=True,
    )
    def create_or_update_chart(
        n_clicks,
        title,
        chart_type,
        x_field,
        x_label,
        color_field,
        aggregation,
        y_field,
        y_label,
        show_legend,
        show_grid,
        current_filter_values,
        modal_filter_values,
        filter_specs,
        edit_chart_id,
        render_trigger,
        chart_configs,
    ):
        logger.debug(f"[MODAL] create_or_update_chart called, n_clicks={n_clicks}")
        logger.debug(f"[MODAL] chart_configs before: {list((chart_configs or {}).keys())}")

        no_change = dict(
            modal_open=no_update,
            alert_open=False,
            alert_children="",
            edit_id=no_update,
            render_trigger=no_update,
            chart_configs=no_update,
        )

        if not n_clicks:
            return no_change

        is_edit_mode = edit_chart_id is not None

        errors = _validate_chart_form(title, x_field, aggregation, y_field, chart_type, color_field)
        if errors:
            return dict(
                modal_open=no_update,
                alert_open=True,
                alert_children=html.Ul([html.Li(e) for e in errors]),
                edit_id=no_update,
                render_trigger=no_update,
                chart_configs=no_update,
            )

        chart_config = _build_chart_config(
            edit_chart_id=edit_chart_id,
            title=title,
            chart_type=chart_type,
            x_field=x_field,
            x_label=x_label,
            color_field=color_field,
            aggregation=aggregation,
            y_field=y_field,
            y_label=y_label,
            show_legend=show_legend,
            show_grid=show_grid,
            collection_name=collection_name,
            filter_specs=filter_specs,
            modal_filter_values=modal_filter_values,
            current_filter_values=current_filter_values,
        )

        from ..chart.factory import ChartFactory

        chart_instance = ChartFactory.create_chart(chart_config)

        updated_chart_configs = dict(chart_configs or {})
        updated_chart_configs[chart_instance.id] = chart_config.to_dict()

        # Register in the chart registry for rendering
        chart_registry.register_active(chart_instance)

        logger.debug(
            f"[MODAL] {'Updated' if is_edit_mode else 'Created'} chart {chart_instance.id}, chart_configs after: {list(updated_chart_configs.keys())}"
        )
        return dict(
            modal_open=False,
            alert_open=False,
            alert_children="",
            edit_id=None,
            render_trigger=no_update,
            chart_configs=updated_chart_configs,
        )


def _validate_chart_form(
    title: str | None,
    x_field: str | None,
    aggregation: str | None,
    y_field: str | None,
    chart_type: str | None,
    color_field: str | None,
) -> list[str]:
    errors = []
    if not title:
        errors.append("Chart title is required.")
    if not x_field:
        errors.append("X-axis field is required.")
    if aggregation != AggregationType.COUNT.value and not y_field:
        errors.append("Y-axis field is required for non-COUNT aggregations.")
    if chart_type == "stacked_bar" and not color_field:
        errors.append("Stacked Bar chart requires a 'Color By' field for stacking.")
    return errors


def _build_chart_config(
    edit_chart_id: str | None,
    title: str,
    chart_type: str,
    x_field: str,
    x_label: str | None,
    color_field: str | None,
    aggregation: str,
    y_field: str | None,
    y_label: str | None,
    show_legend: bool | None,
    show_grid: bool | None,
    collection_name: CollectionName,
    filter_specs: list[dict] | None,
    modal_filter_values: list | None,
    current_filter_values: dict | None,
) -> ChartConfig:
    """
    Build Chart config from modal form values.

    :param filter_specs: Filter specifications from the modal (defines filter structure).
    :param modal_filter_values: Raw filter values from modal inputs (parallel to filter_specs).
    :param current_filter_values: Dashboard-level filters to merge with chart-specific ones.
    """
    from uuid import UUID as UUIDType

    if edit_chart_id:
        chart_id = UUIDType(edit_chart_id) if isinstance(edit_chart_id, str) else edit_chart_id
    else:
        chart_id = uuid4()

    x_axis = AxisConfig(field=x_field, label=x_label or x_field)

    if aggregation != AggregationType.COUNT.value and y_field:
        y_axis = AxisConfig(
            field=y_field,
            label=y_label or y_field,
            aggregation=AggregationType(aggregation),
        )
    else:
        y_axis = AxisConfig(
            field="count",
            label=y_label or "Count",
            aggregation=AggregationType.COUNT,
        )

    color_axis_config = AxisConfig(field=color_field, label=color_field) if color_field else None

    chart_filter_values = {}
    if filter_specs and modal_filter_values:
        for i, spec in enumerate(filter_specs):
            if i < len(modal_filter_values) and modal_filter_values[i]:
                value = modal_filter_values[i]
                if value != "__all__":
                    chart_filter_values[spec["id"]] = value

    combined_filters = {**(current_filter_values or {}), **chart_filter_values}

    chart_config = ChartConfig(
        chart_id=chart_id,
        name=generate_custom_chart_name(chart_id),
        title=title,
        chart_type=AvailableChartTypes(chart_type),
        collection_name=collection_name,
        x_axis=x_axis,
        y_axis=y_axis,
        color_axis=color_axis_config,
        show_legend=show_legend if show_legend is not None else True,
        show_grid=show_grid if show_grid is not None else True,
        is_editable=True,  # Custom charts created by users are editable
        filter_values=chart_filter_values,
    )

    pipeline = build_chart_pipeline(chart_config, combined_filters)
    chart_config.set_query_pipeline(pipeline)

    return chart_config
