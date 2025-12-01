from typing import TYPE_CHECKING

from dash import ctx, no_update
from dash.dependencies import Input, Output, State

from ..chart.chart import Chart
from ..types.common import CollectionName
from .utils import get_current_user_id

if TYPE_CHECKING:
    from ...common.dash.base import Dash
    from ..chart.registry import ChartRegistry
    from ..manager import DashboardManager


def register_dashboard_callbacks(
    dash_app: "Dash",
    prefix: str,
    dataset_type: CollectionName,
    dashboard_manager: "DashboardManager",
    chart_registry: "ChartRegistry",
) -> None:
    _register_dashboard_names(dash_app, prefix, dataset_type, dashboard_manager)
    _register_initial_load(dash_app, prefix, dataset_type, dashboard_manager)
    _register_dashboard_selection(dash_app, prefix, dashboard_manager, chart_registry)
    _register_save_dashboard(dash_app, prefix, dataset_type, dashboard_manager, chart_registry)


def _register_dashboard_names(
    dash_app: "Dash",
    prefix: str,
    dataset_type: CollectionName,
    dashboard_manager: "DashboardManager",
) -> None:
    @dash_app.callback(
        output=dict(options=Output(f"{prefix}-dashboard-selector", "options")),
        inputs=dict(trigger=Input(f"{prefix}-dashboard-selector", "id")),
    )
    def load_dashboard_names(trigger):
        user_id = get_current_user_id()
        if not user_id:
            return dict(options=[])

        names = dashboard_manager.get_dashboard_names(user_id, dataset_type)
        return dict(
            options=[
                {
                    "label": f"{'★ ' if d['is_default'] else ''}{d['name']}",
                    "value": d["dashboard_id"],
                }
                for d in names
            ]
        )


def _register_initial_load(
    dash_app: "Dash",
    prefix: str,
    dataset_type: CollectionName,
    dashboard_manager: "DashboardManager",
) -> None:
    @dash_app.callback(
        output=dict(
            selector_value=Output(f"{prefix}-dashboard-selector", "value"),
            loaded=Output(f"{prefix}-dashboard-loaded", "data"),
        ),
        inputs=dict(collection_name=Input(f"{prefix}-collection-name", "data")),
        state=dict(already_loaded=State(f"{prefix}-dashboard-loaded", "data")),
    )
    def load_default_on_init(collection_name, already_loaded):
        if already_loaded:
            return dict(selector_value=no_update, loaded=no_update)

        user_id = get_current_user_id()
        if not user_id:
            return dict(selector_value=None, loaded=True)

        dashboard, _ = dashboard_manager.load_default_dashboard(user_id, dataset_type)
        if dashboard:
            return dict(selector_value=str(dashboard.dashboard_id), loaded=True)

        return dict(selector_value=None, loaded=True)


def _register_dashboard_selection(
    dash_app: "Dash",
    prefix: str,
    dashboard_manager: "DashboardManager",
    chart_registry: "ChartRegistry",
) -> None:
    @dash_app.callback(
        output=dict(
            empty_state_style=Output(f"{prefix}-empty-state", "style"),
            content_style=Output(f"{prefix}-dashboard-content", "style"),
            dashboard_id=Output(f"{prefix}-current-dashboard-id", "data"),
            name_input=Output(f"{prefix}-dashboard-name-input", "value"),
            active_charts=Output(f"{prefix}-active-charts-store", "data"),
            chart_configs=Output(f"{prefix}-chart-configs-store", "data"),
        ),
        inputs=dict(
            dashboard_id=Input(f"{prefix}-dashboard-selector", "value"),
            create_clicks=Input(f"{prefix}-create-dashboard-btn", "n_clicks"),
        ),
        prevent_initial_call=True,
    )
    def handle_dashboard_selection(dashboard_id, create_clicks):
        triggered = ctx.triggered_id

        if triggered == f"{prefix}-create-dashboard-btn":
            return dict(
                empty_state_style={"display": "none"},
                content_style={"display": "block"},
                dashboard_id=None,
                name_input="New dashboard",
                active_charts=[],
                chart_configs={},
            )

        if not dashboard_id:
            return dict(
                empty_state_style={"display": "block"},
                content_style={"display": "none"},
                dashboard_id=None,
                name_input="New dashboard",
                active_charts=[],
                chart_configs={},
            )

        dashboard, chart_instances = dashboard_manager.load_dashboard_with_charts(dashboard_id)

        if not dashboard:
            return dict(
                empty_state_style={"display": "block"},
                content_style={"display": "none"},
                dashboard_id=None,
                name_input="New dashboard",
                active_charts=[],
                chart_configs={},
            )

        active_chart_ids = []
        chart_configs = {}

        for chart_config in dashboard.charts:
            predefined = chart_registry.get(chart_config.name)
            if predefined:
                active_chart_ids.append(predefined.id)
                chart_configs[predefined.id] = predefined.config.to_dict()
            else:
                chart_id = str(chart_config.chart_id)
                active_chart_ids.append(chart_id)
                chart_configs[chart_id] = chart_config.to_dict()

        return dict(
            empty_state_style={"display": "none"},
            content_style={"display": "block"},
            dashboard_id=str(dashboard.dashboard_id),
            name_input=dashboard.name,
            active_charts=active_chart_ids,
            chart_configs=chart_configs,
        )


def _register_save_dashboard(
    dash_app: "Dash",
    prefix: str,
    dataset_type: CollectionName,
    dashboard_manager: "DashboardManager",
    chart_registry: "ChartRegistry",
) -> None:
    @dash_app.callback(
        output=dict(
            selector_options=Output(f"{prefix}-dashboard-selector", "options", allow_duplicate=True),
            selector_value=Output(f"{prefix}-dashboard-selector", "value", allow_duplicate=True),
            current_dashboard_id=Output(f"{prefix}-current-dashboard-id", "data", allow_duplicate=True),
        ),
        inputs=dict(
            save_clicks=Input(f"{prefix}-save-dashboard-btn", "n_clicks"),
        ),
        state=dict(
            dashboard_id=State(f"{prefix}-current-dashboard-id", "data"),
            dashboard_name=State(f"{prefix}-dashboard-name-input", "value"),
            active_charts=State(f"{prefix}-active-charts-store", "data"),
            chart_configs=State(f"{prefix}-chart-configs-store", "data"),
        ),
        prevent_initial_call=True,
    )
    def save_dashboard(save_clicks, dashboard_id, dashboard_name, active_charts, chart_configs):
        if not save_clicks:
            return dict(
                selector_options=no_update,
                selector_value=no_update,
                current_dashboard_id=no_update,
            )

        user_id = get_current_user_id()
        if not user_id:
            return dict(
                selector_options=no_update,
                selector_value=no_update,
                current_dashboard_id=no_update,
            )

        # Build Chart objects from chart_configs
        charts = []
        for i, chart_id in enumerate(active_charts or []):
            config = (chart_configs or {}).get(chart_id)
            if config:
                try:
                    chart = Chart.from_dict(config)
                    chart.order = i
                    charts.append(chart)
                except (KeyError, ValueError):
                    # Skip invalid chart configs
                    continue

        # Load existing dashboard or create new one
        if dashboard_id:
            dashboard = dashboard_manager.get_dashboard(dashboard_id)
            if dashboard and dashboard.user_id == user_id:
                dashboard.name = dashboard_name or "Untitled Dashboard"
                dashboard.charts = charts
            else:
                # Dashboard not found or doesn't belong to user, create new
                dashboard = dashboard_manager.create_dashboard(
                    dataset_type=dataset_type,
                    user_id=user_id,
                    name=dashboard_name or "Untitled Dashboard",
                )
                dashboard.charts = charts
        else:
            # Create new dashboard
            dashboard = dashboard_manager.create_dashboard(
                dataset_type=dataset_type,
                user_id=user_id,
                name=dashboard_name or "Untitled Dashboard",
            )
            dashboard.charts = charts

        # Save to database
        saved_id = dashboard_manager.save_dashboard(dashboard)

        # Refresh dashboard list
        names = dashboard_manager.get_dashboard_names(user_id, dataset_type)
        options = [
            {
                "label": f"{'★ ' if d['is_default'] else ''}{d['name']}",
                "value": d["dashboard_id"],
            }
            for d in names
        ]

        return dict(
            selector_options=options,
            selector_value=saved_id,
            current_dashboard_id=saved_id,
        )
