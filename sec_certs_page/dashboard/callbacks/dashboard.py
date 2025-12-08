import logging
from typing import TYPE_CHECKING

from dash import ctx, no_update
from dash.dependencies import Input, Output, State

from ..chart.config import ChartConfig
from ..dashboard import Dashboard
from ..dependencies import ComponentID, ComponentIDBuilder
from ..types.common import CollectionName
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
    collection_name: CollectionName,
    dashboard_manager: "DashboardManager",
    chart_registry: "ChartRegistry",
) -> None:
    _register_dashboard_names(dash_app, collection_name, dashboard_manager)
    _register_initial_load(dash_app, collection_name, dashboard_manager)
    _register_dashboard_selection(dash_app, collection_name, dashboard_manager, chart_registry)
    _register_save_dashboard(dash_app, collection_name, dashboard_manager, chart_registry)


def _register_dashboard_names(
    dash_app: "Dash",
    collection_name: CollectionName,
    dashboard_manager: "DashboardManager",
) -> None:
    component_id = ComponentIDBuilder(collection_name)

    @dash_app.callback(
        output=dict(options=Output(component_id(ComponentID.SELECTOR), "options")),
        inputs=dict(loaded=Input(component_id(ComponentID.DASHBOARD_LOADED), "data")),
        prevent_initial_call=True,
    )
    def load_dashboard_names(loaded):
        """Load dashboard names only after initial load is complete."""
        if not loaded:
            return dict(options=[])

        user_id = get_current_user_id()
        if not user_id:
            return dict(options=[])

        names = dashboard_manager.get_dashboard_names(user_id, collection_name)
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
    collection_name: CollectionName,
    dashboard_manager: "DashboardManager",
) -> None:
    component_id = ComponentIDBuilder(collection_name)

    @dash_app.callback(
        output=dict(
            selector_value=Output(component_id(ComponentID.SELECTOR), "value"),
            loaded=Output(component_id(ComponentID.DASHBOARD_LOADED), "data"),
        ),
        inputs=dict(collection_name=Input(component_id(ComponentID.COLLECTION_NAME), "data")),
        state=dict(already_loaded=State(component_id(ComponentID.DASHBOARD_LOADED), "data")),
    )
    def load_default_on_init(collection_name, already_loaded):
        """On initial load of the dashboard page, load the user's default dashboard if any."""
        logger.debug(f"Collection_type: {collection_name}, already_loaded: {already_loaded}")
        if already_loaded:
            return dict(selector_value=no_update, loaded=no_update)

        user_id = get_current_user_id()
        logger.debug(f"user_id: {user_id}")
        if not user_id:
            return dict(selector_value=None, loaded=True)

        dashboard, _ = dashboard_manager.load_default_dashboard(user_id, collection_name)
        if dashboard:
            logger.debug(f"Found default dashboard: {dashboard.dashboard_id}")
            return dict(selector_value=str(dashboard.dashboard_id), loaded=True)

        logger.info("No default dashboard found")
        return dict(selector_value=None, loaded=True)


def _register_dashboard_selection(
    dash_app: "Dash",
    collection_name: CollectionName,
    dashboard_manager: "DashboardManager",
    chart_registry: "ChartRegistry",
) -> None:
    component_id = ComponentIDBuilder(collection_name)

    @dash_app.callback(
        output=dict(
            empty_state_style=Output(component_id(ComponentID.EMPTY_STATE), "style"),
            content_style=Output(component_id(ComponentID.DASHBOARD_CONTENT), "style"),
            dashboard_id=Output(component_id(ComponentID.CURRENT_DASHBOARD_ID), "data"),
            name_input=Output(component_id(ComponentID.DASHBOARD_NAME_INPUT), "value"),
            chart_configs=Output(component_id(ComponentID.CHART_CONFIGS_STORE), "data"),
            selector_value=Output(component_id(ComponentID.SELECTOR), "value", allow_duplicate=True),
            toast_open=Output(component_id(ComponentID.DASHBOARD_TOAST), "is_open"),
            toast_children=Output(component_id(ComponentID.DASHBOARD_TOAST), "children"),
            toast_icon=Output(component_id(ComponentID.DASHBOARD_TOAST), "icon"),
        ),
        inputs=dict(
            dashboard_id=Input(component_id(ComponentID.SELECTOR), "value"),
            create_clicks=Input(component_id(ComponentID.CREATE_BTN), "n_clicks"),
        ),
        state=dict(
            current_dashboard_id=State(component_id(ComponentID.CURRENT_DASHBOARD_ID), "data"),
            selector_options=State(component_id(ComponentID.SELECTOR), "options"),
        ),
        prevent_initial_call=True,
    )
    def handle_dashboard_selection(dashboard_id, create_clicks, current_dashboard_id, selector_options):
        """Handle dashboard selection and creation.

        This callback manages three scenarios:
        1. Creating a new dashboard - keeps current charts, generates new name
        2. Deselecting a dashboard (dashboard_id is None) - shows empty state
        3. Loading an existing dashboard - loads its charts from database
        """
        triggered = ctx.triggered_id
        logger.debug(
            f"[DASHBOARD_SELECT] triggered_id: {triggered}, dashboard_id: {dashboard_id}, current: {current_dashboard_id}"
        )
        logger.debug(f"[DASHBOARD_SELECT] create_clicks: {create_clicks}, selector_options: {selector_options}")

        create_btn_id = component_id(ComponentID.CREATE_BTN)
        selector_id = component_id(ComponentID.SELECTOR)

        if triggered == create_btn_id:
            # Create new dashboard: start fresh with no charts
            new_name = _get_new_dashboard_name(selector_options)
            logger.debug(f"[DASHBOARD_SELECT] Creating new dashboard with name: {new_name}")
            return dict(
                empty_state_style={"display": "none"},
                content_style={"display": "block"},
                dashboard_id=None,  # Mark as new/unsaved
                name_input=new_name,
                chart_configs={},  # Start fresh with no charts
                selector_value=None,  # Clear the dropdown
                toast_open=False,
                toast_children="",
                toast_icon="info",
            )

        # Only process selector changes if triggered by the selector itself
        if triggered != selector_id:
            return dict(
                empty_state_style=no_update,
                content_style=no_update,
                dashboard_id=no_update,
                name_input=no_update,
                chart_configs=no_update,
                selector_value=no_update,
                toast_open=no_update,
                toast_children=no_update,
                toast_icon=no_update,
            )

        if not dashboard_id:
            return dict(
                empty_state_style={"display": "block"},
                content_style={"display": "none"},
                dashboard_id=None,
                name_input="",
                chart_configs={},
                selector_value=None,
                toast_open=False,
                toast_children="",
                toast_icon="info",
            )

        # Check if the selected dashboard is already open
        if current_dashboard_id and str(dashboard_id) == str(current_dashboard_id):
            logger.debug(f"[DASHBOARD_SELECT] Dashboard {dashboard_id} is already open")
            return dict(
                empty_state_style=no_update,
                content_style=no_update,
                dashboard_id=no_update,
                name_input=no_update,
                chart_configs=no_update,
                selector_value=no_update,
                toast_open=True,
                toast_children="This dashboard is already open.",
                toast_icon="info",
            )

        logger.debug(f"[DASHBOARD_SELECT] Loading dashboard {dashboard_id}")
        dashboard, chart_instances = dashboard_manager.load_dashboard_with_charts(dashboard_id)

        if not dashboard:
            return dict(
                empty_state_style={"display": "block"},
                content_style={"display": "none"},
                dashboard_id=None,
                name_input="",
                chart_configs={},
                selector_value=None,
                toast_open=True,
                toast_children="Failed to load the selected dashboard.",
                toast_icon="danger",
            )

        chart_configs = {}

        for chart_config in dashboard.charts:
            predefined = chart_registry.get_predefined(chart_config.name)
            if predefined:
                chart_configs[predefined.id] = predefined.config.to_client_dict()
            else:
                chart_id = str(chart_config.chart_id)
                chart_configs[chart_id] = chart_config.to_client_dict()

        logger.debug(
            f"[DASHBOARD_SELECT] Loaded dashboard with {len(chart_configs)} charts: {list(chart_configs.keys())}"
        )
        return dict(
            empty_state_style={"display": "none"},
            content_style={"display": "block"},
            dashboard_id=str(dashboard.dashboard_id),
            name_input=dashboard.name,
            chart_configs=chart_configs,
            selector_value=no_update,  # Selector already triggered with this value
            toast_open=False,
            toast_children="",
            toast_icon="info",
        )


def _register_save_dashboard(
    dash_app: "Dash",
    collection_name: CollectionName,
    dashboard_manager: "DashboardManager",
    chart_registry: "ChartRegistry",
) -> None:
    component_id = ComponentIDBuilder(collection_name)

    @dash_app.callback(
        output=dict(
            selector_options=Output(component_id(ComponentID.SELECTOR), "options", allow_duplicate=True),
            selector_value=Output(component_id(ComponentID.SELECTOR), "value", allow_duplicate=True),
            current_dashboard_id=Output(component_id(ComponentID.CURRENT_DASHBOARD_ID), "data", allow_duplicate=True),
        ),
        inputs=dict(
            save_clicks=Input(component_id(ComponentID.SAVE_BTN), "n_clicks"),
        ),
        state=dict(
            dashboard_id=State(component_id(ComponentID.CURRENT_DASHBOARD_ID), "data"),
            dashboard_name=State(component_id(ComponentID.DASHBOARD_NAME_INPUT), "value"),
            chart_configs=State(component_id(ComponentID.CHART_CONFIGS_STORE), "data"),
        ),
        prevent_initial_call=True,
    )
    def save_dashboard(save_clicks, dashboard_id, dashboard_name, chart_configs):
        """Save or update a dashboard to the database.

        This callback handles two distinct scenarios:

        1. **Creating a new dashboard** (dashboard_id is None):
           - Occurs when user clicks "Create Dashboard" and then "Save"
           - Creates a new Dashboard instance with a new ID
           - Adds it to the database
           - Updates the selector dropdown with the new dashboard

        2. **Updating an existing dashboard** (dashboard_id is not None):
           - Loads the dashboard from database
           - Validates ownership (user_id must match)
           - Updates name and charts
           - Saves changes back to database

        **Error conditions:**
        - If dashboard_id exists but dashboard not found in database → Error (inconsistent state)
        - If dashboard_id exists but belongs to different user → Security error (rejected)

        The dashboard_id is None when:
        - User clicked "Create Dashboard" button (new unsaved dashboard)
        - User is saving for the first time

        The dashboard_id is not None when:
        - User is editing an existing dashboard loaded from the selector
        - User previously saved this dashboard in the current session

        :param save_clicks: Number of times save button was clicked
        :param dashboard_id: Current dashboard ID from client state (None for new dashboards)
        :param dashboard_name: Dashboard name from the name input field
        :param chart_configs: Dictionary of chart configurations keyed by chart ID
        :return: Updated selector options, selector value, and current dashboard ID
        """
        logger.debug(f"[SAVE_DASHBOARD] Callback triggered - save_clicks: {save_clicks}")
        logger.debug(f"[SAVE_DASHBOARD] chart_configs keys: {list((chart_configs or {}).keys())}")

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
        logger.debug(f"[SAVE_DASHBOARD] Using chart_ids: {chart_ids}")

        charts = []
        for i, chart_id in enumerate(chart_ids):
            # First try to get from chart_configs
            config = (chart_configs or {}).get(chart_id)
            if config:
                try:
                    # chart_configs comes from client (dcc.Store)
                    chart = ChartConfig.from_dict(config, trust_pipeline=False)
                    chart.order = i
                    charts.append(chart)
                    logger.debug(f"[SAVE_DASHBOARD] Chart {chart_id}: loaded from chart_configs")
                except (KeyError, ValueError) as e:
                    logger.debug(f"[SAVE_DASHBOARD] Chart {chart_id}: failed to parse from configs - {e}")
                    continue
            else:
                # Try to get from predefined chart registry
                predefined = chart_registry.get_predefined(chart_id)
                if predefined and predefined.config:
                    chart = predefined.config
                    chart.order = i
                    charts.append(chart)
                    logger.debug(f"[SAVE_DASHBOARD] Chart {chart_id}: loaded from predefined registry")
                else:
                    logger.debug(f"[SAVE_DASHBOARD] Chart {chart_id}: not found in configs or registry")

        logger.debug(f"[SAVE_DASHBOARD] Total charts to save: {len(charts)}")

        # Load existing dashboard or create new one
        is_new_dashboard = dashboard_id is None

        if dashboard_id:
            dashboard = dashboard_manager.get_dashboard(dashboard_id)
            if dashboard and dashboard.user_id == user_id:
                # Update existing dashboard
                dashboard.name = dashboard_name or "Untitled Dashboard"
                dashboard.charts = charts
            elif dashboard and dashboard.user_id != user_id:
                # Security error: trying to modify someone else's dashboard
                logger.error(
                    f"[SAVE_DASHBOARD] User {user_id} attempted to modify dashboard {dashboard_id} owned by {dashboard.user_id}"
                )
                return dict(
                    selector_options=no_update,
                    selector_value=no_update,
                    current_dashboard_id=no_update,
                )
            else:
                # Dashboard ID exists in client state but not in database - inconsistent state
                logger.error(
                    f"[SAVE_DASHBOARD] Dashboard {dashboard_id} not found in database but present in client state"
                )
                return dict(
                    selector_options=no_update,
                    selector_value=no_update,
                    current_dashboard_id=no_update,
                )
        else:
            # Create new dashboard
            dashboard = Dashboard(
                collection_name=collection_name,
                user_id=user_id,
                name=dashboard_name or "Untitled Dashboard",
            )
            dashboard.charts = charts

        # Save to database
        saved_id = dashboard_manager.save_dashboard(dashboard)

        # Refresh dashboard list
        names = dashboard_manager.get_dashboard_names(user_id, collection_name)
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
