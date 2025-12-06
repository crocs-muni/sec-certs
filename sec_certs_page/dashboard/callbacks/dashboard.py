import logging
from typing import TYPE_CHECKING

from dash import ctx, no_update
from dash.dependencies import Input, Output, State

from ..chart.chart import Chart
from ..types.common import CollectionType
from .utils import get_current_user_id

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from ..base import Dash
    from ..chart.registry import ChartRegistry
    from ..manager import DashboardManager


def _get_new_dashboard_name(existing_dashboard_options: list | None) -> str:
    """Generate a new dashboard name with incrementing number based on existing dashboards."""
    count = len(existing_dashboard_options) + 1 if existing_dashboard_options else 1

    if count == 1:
        return "New Dashboard"
    return f"New Dashboard ({count})"


def register_dashboard_callbacks(
    dash_app: "Dash",
    collection_type: CollectionType,
    dashboard_manager: "DashboardManager",
    chart_registry: "ChartRegistry",
) -> None:
    _register_dashboard_names(dash_app, collection_type, dashboard_manager)
    _register_initial_load(dash_app, collection_type, dashboard_manager)
    _register_dashboard_selection(dash_app, collection_type, dashboard_manager, chart_registry)
    _register_save_dashboard(dash_app, collection_type, dashboard_manager, chart_registry)


def _register_dashboard_names(
    dash_app: "Dash",
    collection_type: CollectionType,
    dashboard_manager: "DashboardManager",
) -> None:
    @dash_app.callback(
        output=dict(options=Output(f"{collection_type}-dashboard-selector", "options")),
        inputs=dict(loaded=Input(f"{collection_type}-dashboard-loaded", "data")),
        prevent_initial_call=True,
    )
    def load_dashboard_names(loaded):
        """Load dashboard names only after initial load is complete."""
        if not loaded:
            return dict(options=[])

        user_id = get_current_user_id()
        if not user_id:
            return dict(options=[])

        names = dashboard_manager.get_dashboard_names(user_id, collection_type)
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
    collection_type: CollectionType,
    dashboard_manager: "DashboardManager",
) -> None:
    @dash_app.callback(
        output=dict(
            selector_value=Output(f"{collection_type}-dashboard-selector", "value"),
            loaded=Output(f"{collection_type}-dashboard-loaded", "data"),
        ),
        inputs=dict(collection_name=Input(f"{collection_type}-collection-name", "data")),
        state=dict(already_loaded=State(f"{collection_type}-dashboard-loaded", "data")),
    )
    def load_default_on_init(collection_name, already_loaded):
        print(f"[INIT_LOAD] collection_name: {collection_name}, already_loaded: {already_loaded}")
        if already_loaded:
            return dict(selector_value=no_update, loaded=no_update)

        user_id = get_current_user_id()
        print(f"[INIT_LOAD] user_id: {user_id}")
        if not user_id:
            return dict(selector_value=None, loaded=True)

        dashboard, _ = dashboard_manager.load_default_dashboard(user_id, collection_type)
        if dashboard:
            print(f"[INIT_LOAD] Found default dashboard: {dashboard.dashboard_id}")
            return dict(selector_value=str(dashboard.dashboard_id), loaded=True)

        print("[INIT_LOAD] No default dashboard found")
        return dict(selector_value=None, loaded=True)


def _register_dashboard_selection(
    dash_app: "Dash",
    collection_type: CollectionType,
    dashboard_manager: "DashboardManager",
    chart_registry: "ChartRegistry",
) -> None:
    @dash_app.callback(
        output=dict(
            empty_state_style=Output(f"{collection_type}-empty-state", "style"),
            content_style=Output(f"{collection_type}-dashboard-content", "style"),
            dashboard_id=Output(f"{collection_type}-current-dashboard-id", "data"),
            name_input=Output(f"{collection_type}-dashboard-name-input", "value"),
            chart_configs=Output(f"{collection_type}-chart-configs-store", "data"),
            toast_open=Output(f"{collection_type}-dashboard-toast", "is_open"),
            toast_children=Output(f"{collection_type}-dashboard-toast", "children"),
            toast_icon=Output(f"{collection_type}-dashboard-toast", "icon"),
        ),
        inputs=dict(
            dashboard_id=Input(f"{collection_type}-dashboard-selector", "value"),
            create_clicks=Input(f"{collection_type}-create-dashboard-btn", "n_clicks"),
        ),
        state=dict(
            current_dashboard_id=State(f"{collection_type}-current-dashboard-id", "data"),
            selector_options=State(f"{collection_type}-dashboard-selector", "options"),
        ),
        prevent_initial_call=True,
    )
    def handle_dashboard_selection(dashboard_id, create_clicks, current_dashboard_id, selector_options):
        triggered = ctx.triggered_id
        print(
            f"[DASHBOARD_SELECT] triggered_id: {triggered}, dashboard_id: {dashboard_id}, current: {current_dashboard_id}"
        )

        if triggered == f"{collection_type}-create-dashboard-btn":
            new_name = _get_new_dashboard_name(selector_options)
            return dict(
                empty_state_style={"display": "none"},
                content_style={"display": "block"},
                dashboard_id=None,
                name_input=new_name,
                chart_configs={},
                toast_open=False,
                toast_children="",
                toast_icon="info",
            )

        if not dashboard_id:
            return dict(
                empty_state_style={"display": "block"},
                content_style={"display": "none"},
                dashboard_id=None,
                name_input="",
                chart_configs={},
                toast_open=False,
                toast_children="",
                toast_icon="info",
            )

        # Check if the selected dashboard is already open
        if current_dashboard_id and str(dashboard_id) == str(current_dashboard_id):
            print(f"[DASHBOARD_SELECT] Dashboard {dashboard_id} is already open")
            return dict(
                empty_state_style=no_update,
                content_style=no_update,
                dashboard_id=no_update,
                name_input=no_update,
                chart_configs=no_update,
                toast_open=True,
                toast_children="This dashboard is already open.",
                toast_icon="info",
            )

        print(f"[DASHBOARD_SELECT] Loading dashboard {dashboard_id}")
        dashboard, chart_instances = dashboard_manager.load_dashboard_with_charts(dashboard_id)

        if not dashboard:
            return dict(
                empty_state_style={"display": "block"},
                content_style={"display": "none"},
                dashboard_id=None,
                name_input="",
                chart_configs={},
                toast_open=True,
                toast_children="Failed to load the selected dashboard.",
                toast_icon="danger",
            )

        chart_configs = {}

        for chart_config in dashboard.charts:
            predefined = chart_registry.get(chart_config.name)
            if predefined:
                chart_configs[predefined.id] = predefined.config.to_dict()
            else:
                chart_id = str(chart_config.chart_id)
                chart_configs[chart_id] = chart_config.to_dict()

        print(f"[DASHBOARD_SELECT] Loaded dashboard with {len(chart_configs)} charts: {list(chart_configs.keys())}")
        return dict(
            empty_state_style={"display": "none"},
            content_style={"display": "block"},
            dashboard_id=str(dashboard.dashboard_id),
            name_input=dashboard.name,
            chart_configs=chart_configs,
            toast_open=False,
            toast_children="",
            toast_icon="info",
        )


def _register_save_dashboard(
    dash_app: "Dash",
    collection_type: CollectionType,
    dashboard_manager: "DashboardManager",
    chart_registry: "ChartRegistry",
) -> None:
    @dash_app.callback(
        output=dict(
            selector_options=Output(f"{collection_type}-dashboard-selector", "options", allow_duplicate=True),
            selector_value=Output(f"{collection_type}-dashboard-selector", "value", allow_duplicate=True),
            current_dashboard_id=Output(f"{collection_type}-current-dashboard-id", "data", allow_duplicate=True),
        ),
        inputs=dict(
            save_clicks=Input(f"{collection_type}-save-dashboard-btn", "n_clicks"),
        ),
        state=dict(
            dashboard_id=State(f"{collection_type}-current-dashboard-id", "data"),
            dashboard_name=State(f"{collection_type}-dashboard-name-input", "value"),
            chart_configs=State(f"{collection_type}-chart-configs-store", "data"),
        ),
        prevent_initial_call=True,
    )
    def save_dashboard(save_clicks, dashboard_id, dashboard_name, chart_configs):
        print(f"[SAVE] Callback triggered - save_clicks: {save_clicks}")
        print(f"[SAVE] chart_configs keys: {list((chart_configs or {}).keys())}")

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

        # Use chart_configs as the sole source of truth
        chart_ids = list((chart_configs or {}).keys())
        print(f"[SAVE] Using chart_ids: {chart_ids}")

        charts = []
        for i, chart_id in enumerate(chart_ids):
            # First try to get from chart_configs
            config = (chart_configs or {}).get(chart_id)
            if config:
                try:
                    chart = Chart.from_dict(config)
                    chart.order = i
                    charts.append(chart)
                    print(f"[SAVE] Chart {chart_id}: loaded from chart_configs")
                except (KeyError, ValueError) as e:
                    print(f"[SAVE] Chart {chart_id}: failed to parse from configs - {e}")
                    continue
            else:
                # Try to get from predefined chart registry
                predefined = chart_registry.get_predefined(chart_id)
                if predefined and predefined.config:
                    chart = predefined.config
                    chart.order = i
                    charts.append(chart)
                    print(f"[SAVE] Chart {chart_id}: loaded from predefined registry")
                else:
                    print(f"[SAVE] Chart {chart_id}: not found in configs or registry")

        print(f"[SAVE] Total charts to save: {len(charts)}")

        # Load existing dashboard or create new one
        if dashboard_id:
            dashboard = dashboard_manager.get_dashboard(dashboard_id)
            if dashboard and dashboard.user_id == user_id:
                dashboard.name = dashboard_name or "Untitled Dashboard"
                dashboard.charts = charts
            else:
                # Dashboard not found or doesn't belong to user, create new
                dashboard = dashboard_manager.create_dashboard(
                    collection_type=collection_type,
                    user_id=user_id,
                    name=dashboard_name or "Untitled Dashboard",
                )
                dashboard.charts = charts
        else:
            # Create new dashboard
            dashboard = dashboard_manager.create_dashboard(
                collection_type=collection_type,
                user_id=user_id,
                name=dashboard_name or "Untitled Dashboard",
            )
            dashboard.charts = charts

        # Save to database
        saved_id = dashboard_manager.save_dashboard(dashboard)
        is_new_dashboard = dashboard_id is None

        # Refresh dashboard list
        names = dashboard_manager.get_dashboard_names(user_id, collection_type)
        options = [
            {
                "label": f"{'★ ' if d['is_default'] else ''}{d['name']}",
                "value": d["dashboard_id"],
            }
            for d in names
        ]

        # Only update selector_value if this is a new dashboard
        # For existing dashboards, keep the current selection to avoid triggering
        # the "already open" toast
        return dict(
            selector_options=options,
            selector_value=saved_id if is_new_dashboard else no_update,
            current_dashboard_id=saved_id,
        )
