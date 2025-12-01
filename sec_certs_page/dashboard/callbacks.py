"""
Dash callback registration for the dashboard system.
"""

from datetime import date, datetime, timezone
from typing import TYPE_CHECKING
from uuid import uuid4

import dash_bootstrap_components as dbc
from dash import ALL, MATCH, ctx, dcc, html, no_update
from dash.dependencies import Input, Output, State
from dash.development.base_component import Component
from flask_login import current_user

from .chart.chart import AxisConfig, Chart
from .filters.factory import FilterFactory
from .filters.query_builder import build_chart_pipeline
from .pages.common import get_aggregations_for_type
from .types.chart import AvailableChartTypes
from .types.common import CollectionName
from .types.filter import AggregationType, FilterComponentType

if TYPE_CHECKING:
    from ..common.dash.base import Dash
    from .chart.registry import ChartRegistry
    from .data import DataService
    from .manager import DashboardManager


def register_all_callbacks(
    dash_app: "Dash",
    data_service: "DataService",
    filter_factories: dict[CollectionName, FilterFactory],
    chart_registries: dict[CollectionName, "ChartRegistry"],
    dashboard_manager: "DashboardManager",
) -> None:
    """Register all dashboard callbacks."""
    for dataset_type in CollectionName:
        filter_factory = filter_factories[dataset_type]
        chart_registry = chart_registries[dataset_type]
        prefix = dataset_type.value

        _register_filter_option_callbacks(dash_app, filter_factory, data_service)
        _register_filter_store_callback(dash_app, prefix, filter_factory)
        _register_chart_management_callbacks(dash_app, prefix)
        _register_predefined_chart_options_callback(dash_app, prefix, chart_registry)
        _register_chart_rendering_callback(dash_app, prefix, chart_registry)
        _register_update_all_callback(dash_app, prefix)
        _register_button_state_callbacks(dash_app, prefix)

        _register_dashboard_names_callback(dash_app, prefix, dataset_type, dashboard_manager)
        _register_initial_load_callback(dash_app, prefix, dataset_type, dashboard_manager)
        _register_dashboard_select_callback(dash_app, prefix, dashboard_manager, chart_registry)
        _register_create_dashboard_callback(dash_app, prefix, dataset_type, dashboard_manager)
        _register_load_predefined_callback(dash_app, prefix, dataset_type, dashboard_manager, chart_registry)

        # Chart creation modal callbacks
        _register_available_fields_callback(dash_app, prefix, filter_factory)
        _register_filter_specs_callback(dash_app, prefix, filter_factory)
        _register_chart_modal_callbacks(dash_app, prefix, dataset_type, data_service, chart_registry, filter_factory)

    _register_pattern_matching_callbacks(dash_app, chart_registries)


def _get_current_user_id() -> str | None:
    """Get current user ID from Flask-Login."""
    try:
        if current_user and current_user.is_authenticated:
            return current_user.id
    except RuntimeError:
        pass
    return None


def _register_dashboard_names_callback(
    dash_app: "Dash",
    prefix: str,
    dataset_type: CollectionName,
    dashboard_manager: "DashboardManager",
) -> None:
    """INIT-1: Lazy load dashboard names for dropdown."""

    @dash_app.callback(
        Output(f"{prefix}-dashboard-selector", "options"),
        Input(f"{prefix}-dashboard-selector", "id"),
        prevent_initial_call=False,
    )
    def load_dashboard_names(_):
        user_id = _get_current_user_id()
        if not user_id:
            return []

        names = dashboard_manager.get_dashboard_names(user_id, dataset_type)
        return [
            {
                "label": f"{'★ ' if d['is_default'] else ''}{d['name']}",
                "value": d["dashboard_id"],
            }
            for d in names
        ]


def _register_initial_load_callback(
    dash_app: "Dash",
    prefix: str,
    dataset_type: CollectionName,
    dashboard_manager: "DashboardManager",
) -> None:
    """INIT-3: Load default dashboard on first access."""

    @dash_app.callback(
        Output(f"{prefix}-dashboard-selector", "value"),
        Output(f"{prefix}-dashboard-loaded", "data"),
        Input(f"{prefix}-collection-name", "data"),
        State(f"{prefix}-dashboard-loaded", "data"),
        prevent_initial_call=False,
    )
    def load_default_on_init(collection_name, already_loaded):
        if already_loaded:
            return no_update, no_update

        user_id = _get_current_user_id()
        if not user_id:
            return None, True

        dashboard, _ = dashboard_manager.load_default_dashboard(user_id, dataset_type)
        if dashboard:
            return str(dashboard.dashboard_id), True

        return None, True


def _register_dashboard_select_callback(
    dash_app: "Dash",
    prefix: str,
    dashboard_manager: "DashboardManager",
    chart_registry: "ChartRegistry",
) -> None:
    """INIT-2: Load dashboard and reconstruct charts when selected."""

    @dash_app.callback(
        Output(f"{prefix}-empty-state", "style"),
        Output(f"{prefix}-dashboard-content", "style"),
        Output(f"{prefix}-current-dashboard-id", "data"),
        Output(f"{prefix}-dashboard-name-input", "value"),
        Output(f"{prefix}-active-charts-store", "data"),
        Input(f"{prefix}-dashboard-selector", "value"),
        Input(f"{prefix}-create-dashboard-btn", "n_clicks"),
        Input(f"{prefix}-load-predefined-btn", "n_clicks"),
        prevent_initial_call=True,
    )
    def handle_dashboard_selection(dashboard_id, create_clicks, load_clicks):
        triggered = ctx.triggered_id

        # Handle empty state buttons
        if triggered == f"{prefix}-create-dashboard-btn" or triggered == f"{prefix}-load-predefined-btn":
            return (
                {"display": "none"},
                {"display": "block"},
                None,
                "New dashboard",
                [],
            )

        # Handle dropdown selection
        if not dashboard_id:
            return (
                {"display": "block"},
                {"display": "none"},
                None,
                "New dashboard",
                [],
            )

        dashboard, chart_instances = dashboard_manager.load_dashboard_with_charts(dashboard_id)

        if not dashboard:
            return (
                {"display": "block"},
                {"display": "none"},
                None,
                "New dashboard",
                [],
            )

        # Get chart IDs for active charts store
        # First check if charts are from predefined registry
        active_chart_ids = []
        for chart_config in dashboard.charts:
            predefined = chart_registry.get(chart_config.name)
            if predefined:
                active_chart_ids.append(predefined.id)
            else:
                active_chart_ids.append(str(chart_config.chart_id))

        return (
            {"display": "none"},
            {"display": "block"},
            str(dashboard.dashboard_id),
            dashboard.name,
            active_chart_ids,
        )


def _register_create_dashboard_callback(
    dash_app: "Dash",
    prefix: str,
    dataset_type: CollectionName,
    dashboard_manager: "DashboardManager",
) -> None:
    """INIT-3: Handle 'Create New Dashboard' button."""
    pass  # Logic handled in handle_dashboard_selection


def _register_load_predefined_callback(
    dash_app: "Dash",
    prefix: str,
    dataset_type: CollectionName,
    dashboard_manager: "DashboardManager",
    chart_registry: "ChartRegistry",
) -> None:
    """INIT-3: Handle 'Load Predefined Charts' button - adds all predefined charts."""

    @dash_app.callback(
        Output(f"{prefix}-active-charts-store", "data", allow_duplicate=True),
        Input(f"{prefix}-load-predefined-btn", "n_clicks"),
        State(f"{prefix}-active-charts-store", "data"),
        prevent_initial_call=True,
    )
    def load_predefined_charts(n_clicks, current_charts):
        if not n_clicks:
            return no_update

        predefined_ids = [chart.id for chart in chart_registry]
        return predefined_ids


def _register_filter_option_callbacks(
    dash_app: "Dash",
    filter_factory: FilterFactory,
    data_service: "DataService",
) -> None:
    """Register callbacks to populate filter dropdown options from database."""
    for filter_id, filter_spec in filter_factory.registry.get_all_filters().items():
        if filter_spec.component_params.component_type not in (
            FilterComponentType.DROPDOWN,
            FilterComponentType.MULTI_DROPDOWN,
        ):
            continue

        @dash_app.callback(
            Output(filter_id, "options"),
            Input(filter_id, "id"),
            prevent_initial_call=False,
        )
        def load_options(
            _,
            spec=filter_spec,
            factory=filter_factory,
            ds=data_service,
        ):
            try:
                return ds.get_distinct_values_with_labels(
                    field=spec.database_field,
                    dataset_type=factory.dataset_type,
                )
            except Exception as e:
                print(f"Error loading options for {spec.id}: {e}")
                return []


def _register_filter_store_callback(
    dash_app: "Dash",
    prefix: str,
    filter_factory: FilterFactory,
) -> None:
    """Register callback to collect all filter values into a store."""
    filter_inputs = filter_factory.create_callback_inputs()

    if not filter_inputs:
        return

    @dash_app.callback(
        Output(f"{prefix}-filter-store", "data"),
        filter_inputs,
        prevent_initial_call=False,
    )
    def update_filter_store(*filter_values) -> dict:
        return filter_factory.collect_filter_values(*filter_values)


def _register_chart_management_callbacks(dash_app: "Dash", prefix: str) -> None:
    """Register callbacks for adding/removing charts from active list."""

    @dash_app.callback(
        Output(f"{prefix}-active-charts-store", "data", allow_duplicate=True),
        Input(f"{prefix}-add-chart-btn", "n_clicks"),
        Input({"type": "remove-chart", "index": ALL}, "n_clicks"),
        State(f"{prefix}-chart-selector", "value"),
        State(f"{prefix}-active-charts-store", "data"),
        prevent_initial_call=True,
    )
    def manage_charts(
        add_clicks: int,
        remove_clicks: list[int],
        selected_chart_id: str | None,
        current_charts: list | None,
    ) -> list:
        if current_charts is None:
            current_charts = []

        triggered_id = ctx.triggered_id

        if triggered_id == f"{prefix}-add-chart-btn":
            if selected_chart_id and selected_chart_id not in current_charts:
                current_charts.append(selected_chart_id)

        elif isinstance(triggered_id, dict) and triggered_id.get("type") == "remove-chart":
            chart_to_remove = triggered_id.get("index")
            if chart_to_remove in current_charts:
                current_charts.remove(chart_to_remove)

        return current_charts


def _register_predefined_chart_options_callback(
    dash_app: "Dash",
    prefix: str,
    chart_registry: "ChartRegistry",
) -> None:
    """Populate the predefined chart dropdown with available charts from registry."""

    @dash_app.callback(
        Output(f"{prefix}-chart-selector", "options"),
        Input(f"{prefix}-dashboard-content", "style"),
        prevent_initial_call=False,
    )
    def populate_predefined_charts(_):
        """Load predefined chart options from the chart registry."""
        return [
            {
                "label": chart.title,
                "value": chart.id,
            }
            for chart in chart_registry
        ]


def _create_chart_wrapper(chart_id: str, title: str, chart_component: Component) -> dbc.Card:
    """
    Create a Bootstrap card wrapper for a chart with controls.

    :param chart_id: Unique chart identifier
    :param title: Chart title
    :param chart_component: The chart component to wrap
    :return: Card containing the chart with header controls
    """
    return dbc.Card(
        id={"type": "chart-wrapper", "index": chart_id},
        className="mb-4 shadow-sm",
        children=[
            dbc.CardHeader(
                className="d-flex justify-content-between align-items-center",
                children=[
                    html.H5(title, className="mb-0"),
                    dbc.ButtonGroup(
                        size="sm",
                        children=[
                            dbc.Button(
                                html.I(className="fas fa-sync-alt"),
                                id={"type": "chart-refresh", "index": chart_id},
                                color="success",
                                outline=True,
                                title="Refresh this chart",
                            ),
                            dbc.Button(
                                html.I(className="fas fa-times"),
                                id={"type": "remove-chart", "index": chart_id},
                                color="danger",
                                outline=True,
                                title="Remove this chart",
                            ),
                        ],
                    ),
                ],
            ),
            dbc.CardBody(
                id={"type": "chart-content", "index": chart_id},
                children=chart_component,
            ),
        ],
    )


def _register_chart_rendering_callback(
    dash_app: "Dash",
    prefix: str,
    chart_registry: "ChartRegistry",
) -> None:
    """Register callback to render all active charts."""

    @dash_app.callback(
        Output(f"{prefix}-chart-container", "children"),
        Input(f"{prefix}-active-charts-store", "data"),
        Input(f"{prefix}-render-trigger", "data"),
        State(f"{prefix}-filter-store", "data"),
        prevent_initial_call=False,
    )
    def render_charts(
        chart_ids: list | None,
        render_trigger: int | None,
        filter_values: dict | None,
    ) -> list[Component]:
        if not chart_ids:
            return [
                dbc.Alert(
                    [
                        html.I(className="fas fa-info-circle me-2"),
                        "No charts added yet. Select a chart and click 'Add Chart'.",
                    ],
                    color="info",
                    className="text-center",
                ),
            ]

        rendered = []

        for chart_id in chart_ids:
            chart = chart_registry.get(chart_id)

            if not chart:
                rendered.append(
                    dbc.Alert(
                        [
                            html.I(className="fas fa-exclamation-triangle me-2"),
                            f"Chart '{chart_id}' not found.",
                        ],
                        color="warning",
                    )
                )
                continue

            try:
                chart_component = chart.render(filter_values or {})
                rendered.append(_create_chart_wrapper(chart_id, chart.title, chart_component))
            except Exception as e:
                rendered.append(
                    dbc.Alert(
                        [
                            html.I(className="fas fa-exclamation-circle me-2"),
                            f"Error rendering chart '{chart_id}': {str(e)}",
                        ],
                        color="danger",
                    )
                )

        return rendered


def _register_update_all_callback(dash_app: "Dash", prefix: str) -> None:
    @dash_app.callback(
        Output(f"{prefix}-render-trigger", "data"),
        Input(f"{prefix}-update-all-btn", "n_clicks"),
        State(f"{prefix}-render-trigger", "data"),
        prevent_initial_call=True,
    )
    def trigger_update_all(n_clicks: int, current_trigger: int | None) -> int:
        return (current_trigger or 0) + 1


def _register_button_state_callbacks(dash_app: "Dash", prefix: str) -> None:
    @dash_app.callback(
        Output(f"{prefix}-update-all-btn", "disabled"),
        Output(f"{prefix}-save-dashboard-btn", "disabled"),
        Input(f"{prefix}-filter-store", "data"),
        Input(f"{prefix}-active-charts-store", "data"),
        prevent_initial_call=False,
    )
    def update_button_states(
        filter_values: dict | None,
        active_charts: list | None,
    ) -> tuple[bool, bool]:
        has_active_filters = bool(filter_values and len(filter_values) > 0)
        has_charts = bool(active_charts and len(active_charts) > 0)

        update_disabled = not has_charts
        save_disabled = not (has_charts and has_active_filters)

        return update_disabled, save_disabled


def _register_pattern_matching_callbacks(
    dash_app: "Dash",
    chart_registries: dict[CollectionName, "ChartRegistry"],
) -> None:
    @dash_app.callback(
        Output({"type": "chart-content", "index": MATCH}, "children"),
        Input({"type": "chart-refresh", "index": MATCH}, "n_clicks"),
        State({"type": "chart-wrdash_apper", "index": MATCH}, "id"),
        prevent_initial_call=True,
    )
    def refresh_single_chart(n_clicks: int, wrdash_apper_id: dict | None):
        if not n_clicks:
            return no_update

        chart_id = wrdash_apper_id.get("index") if wrdash_apper_id else None
        if not chart_id:
            return no_update

        for registry in chart_registries.values():
            chart = registry.get(chart_id)
            if chart:
                try:
                    return chart.render()
                except Exception as e:
                    return html.P(f"Error refreshing chart: {str(e)}", style={"color": "red"})

        return html.P(f"Chart '{chart_id}' not found.", style={"color": "red"})


def _register_available_fields_callback(
    dash_app: "Dash",
    prefix: str,
    filter_factory: FilterFactory,
) -> None:
    """Populate available fields store from FilterFactory on page load."""

    @dash_app.callback(
        Output(f"{prefix}-available-fields", "data"),
        Input(f"{prefix}-collection-name", "data"),
        prevent_initial_call=False,
    )
    def load_available_fields(_):
        return filter_factory.get_available_fields()


def _register_filter_specs_callback(
    dash_app: "Dash",
    prefix: str,
    filter_factory: FilterFactory,
) -> None:
    """Populate filter specs store from FilterFactory on page load."""

    @dash_app.callback(
        Output(f"{prefix}-filter-specs", "data"),
        Input(f"{prefix}-collection-name", "data"),
        prevent_initial_call=False,
    )
    def load_filter_specs(_):
        return filter_factory.get_filter_specs_for_modal()


def _register_chart_modal_callbacks(
    dash_app: "Dash",
    prefix: str,
    dataset_type: CollectionName,
    data_service: "DataService",
    chart_registry: "ChartRegistry",
    filter_factory: FilterFactory,
) -> None:
    """Register callbacks for the chart creation modal."""

    # Open/close modal
    @dash_app.callback(
        Output(f"{prefix}-create-chart-modal", "is_open"),
        Input(f"{prefix}-open-create-chart-modal-btn", "n_clicks"),
        Input(f"{prefix}-modal-cancel-btn", "n_clicks"),
        Input(f"{prefix}-modal-create-btn", "n_clicks"),
        State(f"{prefix}-create-chart-modal", "is_open"),
        prevent_initial_call=True,
    )
    def toggle_modal(open_clicks, cancel_clicks, create_clicks, is_open):
        triggered = ctx.triggered_id
        if triggered == f"{prefix}-open-create-chart-modal-btn":
            return True
        if triggered == f"{prefix}-modal-cancel-btn":
            return False
        # Modal will be closed by create callback if successful
        return is_open

    # Generate filter UI components dynamically based on filter specs
    @dash_app.callback(
        Output(f"{prefix}-modal-filters-container", "children"),
        Input(f"{prefix}-filter-specs", "data"),
        prevent_initial_call=False,
    )
    def generate_modal_filter_ui(filter_specs):
        """Generate filter components for the chart creation modal based on component type."""
        if not filter_specs:
            return html.P("No filters available.", className="text-muted")

        def create_filter_component(spec: dict, field_id: dict) -> Component:
            """Create appropriate filter component based on type."""
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
                        dbc.Button(
                            html.I(className="fas fa-times"),
                            id={"type": f"{prefix}-clear-filter", "field": spec["id"]},
                            color="secondary",
                            outline=True,
                            size="sm",
                            className="px-2",
                            title="Clear",
                        ),
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
                                    placeholder=spec.get("placeholder") or "DD-MM-YYYY",
                                    display_format="DD-MM-YYYY",
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
                        dbc.Button(
                            html.I(className="fas fa-times"),
                            id={"type": f"{prefix}-clear-filter", "field": spec["id"]},
                            color="secondary",
                            outline=True,
                            size="sm",
                            className="px-2",
                            title="Clear",
                        ),
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
                                    display_format="DD-MM-YYYY",
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
                        dbc.Button(
                            html.I(className="fas fa-times"),
                            id={"type": f"{prefix}-clear-filter", "field": spec["field"]},
                            color="secondary",
                            outline=True,
                            size="sm",
                            className="px-2",
                            title="Clear",
                        ),
                    ],
                )
            if component_type == "checkbox":
                return dbc.Checkbox(id=field_id, label=spec["label"])

            # Default: dropdown or multi_dropdown
            if component_type == "multi_dropdown":
                # Multi-select with Select All / Clear buttons
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
                                    id={"type": f"{prefix}-select-all-filter", "field": spec["id"]},
                                    color="link",
                                    size="sm",
                                    className="p-0 text-decoration-none",
                                ),
                                html.Span("·", className="text-muted"),
                                dbc.Button(
                                    "Clear",
                                    id={"type": f"{prefix}-clear-filter", "field": spec["id"]},
                                    color="link",
                                    size="sm",
                                    className="p-0 text-decoration-none",
                                ),
                            ],
                        ),
                    ],
                )

            # Single-select dropdown
            return dcc.Dropdown(
                id=field_id,
                options=[],
                placeholder=placeholder,
                multi=False,
                clearable=True,
                className="dash-bootstrap",
            )

        filter_rows = []
        for i in range(0, len(filter_specs), 2):
            cols = []
            for spec in filter_specs[i : i + 2]:
                component_type = spec.get("component_type", "dropdown")
                field_id = {"type": f"{prefix}-modal-filter", "field": spec["id"]}
                filter_component = create_filter_component(spec, field_id)

                children = [filter_component]
                if component_type != "checkbox":
                    children.insert(0, dbc.Label(spec["label"], className="fw-bold small"))
                if spec.get("help_text"):
                    children.append(html.Small(spec["help_text"], className="text-muted"))

                cols.append(dbc.Col(width=12, md=6, children=children, className="mb-2"))

            filter_rows.append(dbc.Row(cols, className="g-2"))

        return filter_rows

    # Populate modal filter options (for each dynamic filter dropdown)
    @dash_app.callback(
        Output({"type": f"{prefix}-modal-filter", "field": ALL}, "options"),
        Input(f"{prefix}-filter-specs", "data"),
        prevent_initial_call=False,
    )
    def populate_modal_filter_options(filter_specs):
        """Populate options for all modal filter dropdowns.

        Adds an "All" option at the top for categorical dropdowns to make
        it easy to clear the filter selection.
        """
        if not filter_specs:
            return []

        options_list = []
        for spec in filter_specs:
            field = spec["field"]
            operator = spec.get("operator", "")
            component_type = spec.get("component_type", "dropdown")

            # Only populate options for dropdown types
            if component_type not in ("dropdown", "multi_dropdown"):
                options_list.append([])
                continue

            # Get unique values for this field from the data service
            try:
                # Special handling for YEAR_IN operator - get years, not raw field values
                if operator == "$year_in":
                    unique_values = data_service.get_unique_values(dataset_type, "year_from")
                else:
                    unique_values = data_service.get_unique_values(dataset_type, field)

                options = [{"label": str(v), "value": v} for v in unique_values if v is not None]

                # Add "All" option at the top for single-select dropdowns
                # For multi-select, clearing is done via the clearable X button
                if component_type == "dropdown" and options:
                    options.insert(0, {"label": "── Not selected ──", "value": "__all__"})

                options_list.append(options)
            except Exception:
                options_list.append([])

        return options_list

    # Clear filter button callback - clears the corresponding filter value
    @dash_app.callback(
        Output({"type": f"{prefix}-modal-filter", "field": MATCH}, "value"),
        Input({"type": f"{prefix}-clear-filter", "field": MATCH}, "n_clicks"),
        prevent_initial_call=True,
    )
    def clear_filter_value(n_clicks):
        """Clear filter value when clear button is clicked."""
        if n_clicks:
            return None
        return no_update

    # Select All button callback - selects all available options for multi-select
    @dash_app.callback(
        Output({"type": f"{prefix}-modal-filter", "field": MATCH}, "value", allow_duplicate=True),
        Input({"type": f"{prefix}-select-all-filter", "field": MATCH}, "n_clicks"),
        State({"type": f"{prefix}-modal-filter", "field": MATCH}, "options"),
        prevent_initial_call=True,
    )
    def select_all_filter_values(n_clicks, options):
        """Select all available options when Select All button is clicked."""
        if n_clicks and options:
            # Extract all values from options (skip any special values like __all__)
            all_values = [opt["value"] for opt in options if opt.get("value") != "__all__"]
            return all_values
        return no_update

    # Populate X-axis field dropdown from available fields
    @dash_app.callback(
        Output(f"{prefix}-modal-x-field", "options"),
        Output(f"{prefix}-modal-color-field", "options"),
        Input(f"{prefix}-available-fields", "data"),
        prevent_initial_call=False,
    )
    def populate_axis_field_options(available_fields):
        if not available_fields:
            return [], []
        options = [{"label": f["label"], "value": f["value"]} for f in available_fields]
        return options, options

    # Update aggregation options based on selected X-field data type
    @dash_app.callback(
        Output(f"{prefix}-modal-aggregation", "options"),
        Input(f"{prefix}-modal-x-field", "value"),
        State(f"{prefix}-available-fields", "data"),
        prevent_initial_call=True,
    )
    def update_aggregation_options(x_field_value, available_fields):
        if not x_field_value or not available_fields:
            # Default to all aggregations
            return [{"label": agg.value.upper(), "value": agg.value} for agg in AggregationType]

        # Find the selected field's data type
        field_info = next((f for f in available_fields if f["value"] == x_field_value), None)
        if field_info:
            return get_aggregations_for_type(field_info["data_type"])

        return [{"label": agg.value.upper(), "value": agg.value} for agg in AggregationType]

    # Enable/disable Y-field based on aggregation type and populate numeric fields
    @dash_app.callback(
        Output(f"{prefix}-modal-y-field", "disabled"),
        Output(f"{prefix}-modal-y-field", "options"),
        Output(f"{prefix}-modal-y-field-help", "children"),
        Input(f"{prefix}-modal-aggregation", "value"),
        State(f"{prefix}-available-fields", "data"),
        prevent_initial_call=False,
    )
    def update_y_field_state(aggregation_value, available_fields):
        if aggregation_value == AggregationType.COUNT.value:
            return True, [], "Not required for COUNT aggregation."

        # Filter to numeric fields only for SUM, AVG, MIN, MAX
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

        return False, numeric_fields, help_text

    # Auto-fill X-axis label when field is selected
    @dash_app.callback(
        Output(f"{prefix}-modal-x-label", "value"),
        Input(f"{prefix}-modal-x-field", "value"),
        State(f"{prefix}-available-fields", "data"),
        State(f"{prefix}-modal-x-label", "value"),
        prevent_initial_call=True,
    )
    def auto_fill_x_label(x_field_value, available_fields, current_label):
        if current_label:  # Don't override if user already entered something
            return no_update

        if x_field_value and available_fields:
            field_info = next((f for f in available_fields if f["value"] == x_field_value), None)
            if field_info:
                return field_info["label"]

        return ""

    # Show help text for chart type selection
    @dash_app.callback(
        Output(f"{prefix}-chart-type-help", "children"),
        Input(f"{prefix}-modal-chart-type", "value"),
        prevent_initial_call=False,
    )
    def show_chart_type_help(chart_type):
        """Show contextual help for selected chart type."""
        if chart_type == "stacked_bar":
            return dbc.Alert(
                [
                    html.I(className="fas fa-info-circle me-2"),
                    "Stacked Bar requires a ",
                    html.Strong("Color By"),
                    " field to stack values. Expand 'Secondary Grouping' below.",
                ],
                color="info",
                className="mb-0 py-2 small",
            )
        return None

    # Toggle Color By collapse section
    @dash_app.callback(
        Output(f"{prefix}-color-by-collapse", "is_open"),
        Output(f"{prefix}-color-by-icon", "className"),
        Input(f"{prefix}-color-by-toggle", "n_clicks"),
        State(f"{prefix}-color-by-collapse", "is_open"),
        prevent_initial_call=True,
    )
    def toggle_color_by_section(n_clicks, is_open):
        if n_clicks:
            new_state = not is_open
            icon_class = "fas fa-chevron-down me-2" if new_state else "fas fa-chevron-right me-2"
            return new_state, icon_class
        return is_open, "fas fa-chevron-right me-2"

    # Create chart from modal
    @dash_app.callback(
        Output(f"{prefix}-active-charts-store", "data", allow_duplicate=True),
        Output(f"{prefix}-create-chart-modal", "is_open", allow_duplicate=True),
        Output(f"{prefix}-modal-validation-alert", "is_open"),
        Output(f"{prefix}-modal-validation-alert", "children"),
        Input(f"{prefix}-modal-create-btn", "n_clicks"),
        State(f"{prefix}-modal-chart-title", "value"),
        State(f"{prefix}-modal-chart-type", "value"),
        State(f"{prefix}-modal-x-field", "value"),
        State(f"{prefix}-modal-x-label", "value"),
        State(f"{prefix}-modal-color-field", "value"),
        State(f"{prefix}-modal-aggregation", "value"),
        State(f"{prefix}-modal-y-field", "value"),
        State(f"{prefix}-modal-y-label", "value"),
        State(f"{prefix}-modal-show-legend", "value"),
        State(f"{prefix}-modal-show-grid", "value"),
        State(f"{prefix}-active-charts-store", "data"),
        State(f"{prefix}-filter-store", "data"),
        State({"type": f"{prefix}-modal-filter", "field": ALL}, "value"),
        State(f"{prefix}-filter-specs", "data"),
        prevent_initial_call=True,
    )
    def create_custom_chart(
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
        active_charts,
        current_filter_values,
        modal_filter_values,
        filter_specs,
    ):
        if not n_clicks:
            return no_update, no_update, False, ""

        # Validation
        errors = []
        if not title:
            errors.append("Chart title is required.")
        if not x_field:
            errors.append("X-axis field is required.")
        if aggregation != AggregationType.COUNT.value and not y_field:
            errors.append("Y-axis field is required for non-COUNT aggregations.")
        if chart_type == "stacked_bar" and not color_field:
            errors.append("Stacked Bar chart requires a 'Color By' field for stacking.")

        if errors:
            return no_update, no_update, True, html.Ul([html.Li(e) for e in errors])

        # Create the chart configuration
        chart_id = uuid4()

        x_axis = AxisConfig(
            field=x_field,
            label=x_label or x_field,
        )

        y_axis = None
        if aggregation != AggregationType.COUNT.value and y_field:
            y_axis = AxisConfig(
                field=y_field,
                label=y_label or y_field,
                aggregation=AggregationType(aggregation),
            )
        else:
            # For COUNT, create a y_axis with count aggregation
            y_axis = AxisConfig(
                field="count",
                label=y_label or "Count",
                aggregation=AggregationType.COUNT,
            )

        # Create color axis for secondary grouping (Color By)
        color_axis_config = None
        if color_field:
            color_axis_config = AxisConfig(
                field=color_field,
                label=color_field,
            )

        # Collect chart-specific filter values from the modal
        chart_filter_values = {}
        if filter_specs and modal_filter_values:
            for i, spec in enumerate(filter_specs):
                if i < len(modal_filter_values) and modal_filter_values[i]:
                    value = modal_filter_values[i]
                    # Skip "__all__" values (means no filter)
                    if value == "__all__":
                        continue
                    # Use filter ID as key (matches what build_query_from_filters expects)
                    chart_filter_values[spec["id"]] = value

        # Combine dashboard-level filters with chart-specific filters
        # Chart filters take precedence if there's overlap
        combined_filters = {**(current_filter_values or {}), **chart_filter_values}

        chart_config = Chart(
            chart_id=chart_id,
            name=f"custom-{chart_id}",
            title=title,
            chart_type=AvailableChartTypes(chart_type),
            collection_type=dataset_type,
            x_axis=x_axis,
            y_axis=y_axis,
            color_axis=color_axis_config,
            show_legend=show_legend if show_legend is not None else True,
            show_grid=show_grid if show_grid is not None else True,
            filter_values=chart_filter_values,  # Store chart-specific filters
        )

        # Build the MongoDB aggregation pipeline from chart config and combined filters
        pipeline = build_chart_pipeline(chart_config, combined_filters)
        chart_config.set_query_pipeline(pipeline)

        # Create chart instance using ChartFactory
        from .chart.factory import ChartFactory

        chart_instance = ChartFactory.create_chart(chart_config, data_service)

        # Register the chart
        chart_registry.register(chart_instance)

        # Add to active charts
        new_active_charts = (active_charts or []) + [chart_instance.id]

        return new_active_charts, False, False, ""
