"""
Dash callback registration for the dashboard system.
"""

from typing import TYPE_CHECKING

from dash import ALL, MATCH, ctx, html, no_update
from dash.dependencies import Input, Output, State
from dash.development.base_component import Component
from flask_login import current_user

from .filters.factory import FilterFactory
from .types.common import CollectionName
from .types.filter import FilterComponentType

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
        _register_chart_rendering_callback(dash_app, prefix, chart_registry)
        _register_update_all_callback(dash_app, prefix)
        _register_button_state_callbacks(dash_app, prefix)

        # INIT callbacks
        _register_dashboard_names_callback(dash_app, prefix, dataset_type, dashboard_manager)
        _register_initial_load_callback(dash_app, prefix, dataset_type, dashboard_manager)
        _register_dashboard_select_callback(dash_app, prefix, dashboard_manager, chart_registry)
        _register_create_dashboard_callback(dash_app, prefix, dataset_type, dashboard_manager)
        _register_load_predefined_callback(dash_app, prefix, dataset_type, dashboard_manager, chart_registry)

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
                html.P(
                    "No charts added yet. Select a chart and click 'Add Chart'.",
                    style={"color": "gray"},
                )
            ]

        rendered = []

        for chart_id in chart_ids:
            chart = chart_registry.get(chart_id)

            if not chart:
                rendered.append(
                    html.Div(
                        html.P(f"Error: Chart '{chart_id}' not found.", style={"color": "red"}),
                        style={"border": "1px solid #ddd", "padding": "10px", "marginBottom": "10px"},
                    )
                )
                continue

            try:
                chart_component = chart.render()
                rendered.append(_create_chart_wrdash_apper(chart_id, chart.title, chart_component))

            except Exception as e:
                rendered.append(
                    html.Div(
                        [
                            html.H4(chart.title),
                            html.P(f"Error rendering: {str(e)}", style={"color": "red"}),
                        ],
                        style={"border": "1px solid #ddd", "padding": "10px", "marginBottom": "10px"},
                    )
                )

        return rendered


def _create_chart_wrdash_apper(chart_id: str, title: str, chart_component: Component) -> html.Div:
    return html.Div(
        id={"type": "chart-wrdash_apper", "index": chart_id},
        children=[
            html.Div(
                [
                    html.H4(title, style={"display": "inline-block", "margin": "0"}),
                    html.Div(
                        [
                            html.Button(
                                "🔄",
                                id={"type": "chart-refresh", "index": chart_id},
                                title="Refresh this chart",
                                style={
                                    "background": "#4CAF50",
                                    "color": "white",
                                    "border": "none",
                                    "borderRadius": "4px",
                                    "padding": "5px 10px",
                                    "marginRight": "5px",
                                    "cursor": "pointer",
                                },
                            ),
                            html.Button(
                                "×",
                                id={"type": "remove-chart", "index": chart_id},
                                title="Remove this chart",
                                style={
                                    "background": "red",
                                    "color": "white",
                                    "border": "none",
                                    "borderRadius": "50%",
                                    "width": "25px",
                                    "height": "25px",
                                    "cursor": "pointer",
                                },
                            ),
                        ],
                        style={"float": "right"},
                    ),
                ],
                style={"marginBottom": "10px", "overflow": "hidden"},
            ),
            html.Div(
                id={"type": "chart-content", "index": chart_id},
                children=chart_component,
            ),
        ],
        style={"border": "1px solid #ddd", "padding": "15px", "marginBottom": "15px", "borderRadius": "5px"},
    )


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
