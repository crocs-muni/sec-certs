import logging
from typing import TYPE_CHECKING

import dash_bootstrap_components as dbc
from dash import ALL, MATCH, ctx, html, no_update
from dash.dependencies import Input, Output, State

from ..chart.chart import Chart
from ..chart.factory import ChartFactory
from ..types.common import CollectionName
from .utils import create_chart_wrapper

if TYPE_CHECKING:
    from ..base import Dash
    from ..chart.registry import ChartRegistry
    from ..data import DataService


logger = logging.getLogger(__name__)


def register_chart_callbacks(
    dash_app: "Dash",
    collection_name: CollectionName,
    chart_registry: "ChartRegistry",
    data_service: "DataService",
) -> None:
    _register_chart_management(dash_app, collection_name, chart_registry)
    _register_predefined_chart_options(dash_app, collection_name, chart_registry)
    _register_chart_rendering(dash_app, collection_name, chart_registry, data_service)
    _register_update_all(dash_app, collection_name)


def register_pattern_matching_callbacks(
    dash_app: "Dash",
    chart_registries: dict[CollectionName, "ChartRegistry"],
) -> None:
    """Must be registered once globally since pattern-matching callbacks match across all collections."""

    @dash_app.callback(
        output=dict(content=Output({"type": "chart-content", "index": MATCH}, "children")),
        inputs=dict(n_clicks=Input({"type": "chart-refresh", "index": MATCH}, "n_clicks")),
        state=dict(wrapper_id=State({"type": "chart-wrapper", "index": MATCH}, "id")),
        prevent_initial_call=True,
    )
    def refresh_single_chart(n_clicks, wrapper_id):
        """When user clicks the chart-refresh button we re-render it."""
        if not n_clicks:
            return dict(content=no_update)

        chart_id = wrapper_id.get("index") if wrapper_id else None
        if not chart_id:
            return dict(content=no_update)

        for registry in chart_registries.values():
            chart = registry.get(chart_id)
            if chart:
                try:
                    return dict(content=chart.render())
                except Exception as e:
                    return dict(content=html.P(f"Error refreshing chart: {str(e)}", style={"color": "red"}))

        return dict(content=html.P(f"Chart '{chart_id}' not found.", style={"color": "red"}))


def _register_chart_management(
    dash_app: "Dash", collection_name: CollectionName, chart_registry: "ChartRegistry"
) -> None:
    @dash_app.callback(
        output=dict(
            chart_configs=Output(f"{collection_name}-chart-configs-store", "data", allow_duplicate=True),
        ),
        inputs=dict(
            add_clicks=Input(f"{collection_name}-add-chart-btn", "n_clicks"),
            remove_clicks=Input({"type": "remove-chart", "index": ALL}, "n_clicks"),
        ),
        state=dict(
            selected_chart_id=State(f"{collection_name}-chart-selector", "value"),
            current_configs=State(f"{collection_name}-chart-configs-store", "data"),
        ),
        prevent_initial_call=True,
    )
    def manage_charts(add_clicks, remove_clicks, selected_chart_id, current_configs):
        """When user clicks the remove-chart button or the add-chart-btn we handle those."""

        if current_configs is None:
            current_configs = {}

        triggered_id = ctx.triggered_id

        if triggered_id == f"{collection_name}-add-chart-btn":
            if selected_chart_id and selected_chart_id not in current_configs:
                # Add the chart config (for predefined charts, get from registry)
                predefined = chart_registry.get_predefined(selected_chart_id)
                if predefined and predefined.config:
                    current_configs[selected_chart_id] = predefined.config.to_dict()
                else:
                    logger.debug(f"[CHART_MGMT] Chart {selected_chart_id} not found in predefined registry")

        elif isinstance(triggered_id, dict) and triggered_id.get("type") == "remove-chart":
            # Check if this was an actual click (n_clicks > 0) vs just a new component appearing
            # When a new chart is rendered, the pattern-matching callback fires with n_clicks=0
            chart_to_remove = triggered_id.get("index")

            # Find which button was actually clicked by checking ctx.triggered
            actual_click = False
            for trigger in ctx.triggered:
                if trigger.get("value") and trigger.get("value") > 0:
                    actual_click = True
                    break

            if actual_click and chart_to_remove in current_configs:
                del current_configs[chart_to_remove]
                logger.info("Removed chart", extra={"chart_id": chart_to_remove})
            else:
                logger.debug(
                    "Ignored remove trigger",
                    extra={"chart_id": chart_to_remove, "reason": "n_clicks=0 or chart missing"},
                )

        logger.debug(
            "Chart configs after update",
            extra={"chart_ids": list(current_configs.keys())},
        )

        return dict(chart_configs=current_configs)


def _register_predefined_chart_options(
    dash_app: "Dash",
    collection_name: CollectionName,
    chart_registry: "ChartRegistry",
) -> None:
    @dash_app.callback(
        output=dict(options=Output(f"{collection_name}-chart-selector", "options")),
        inputs=dict(dashboard_loaded=Input(f"{collection_name}-dashboard-loaded", "data")),
        prevent_initial_call=True,
    )
    def populate_predefined_charts(dashboard_loaded):
        """Populate chart selector options - only after dashboard is loaded."""
        if not dashboard_loaded:
            return dict(options=[])
        return dict(options=[{"label": chart.title, "value": chart.id} for chart in chart_registry])


def _register_chart_rendering(
    dash_app: "Dash",
    collection_name: CollectionName,
    chart_registry: "ChartRegistry",
    data_service: "DataService",
) -> None:
    @dash_app.callback(
        output=dict(children=Output(f"{collection_name}-chart-container", "children")),
        inputs=dict(
            render_trigger=Input(f"{collection_name}-render-trigger", "data"),
            chart_configs=Input(f"{collection_name}-chart-configs-store", "data"),
        ),
        state=dict(filter_values=State(f"{collection_name}-filter-store", "data")),
    )
    def render_charts(render_trigger, chart_configs, filter_values):
        """When the user clicks the update-all-btn or we load first we render the charts."""
        chart_ids = list((chart_configs or {}).keys())
        if not chart_ids:
            return dict(
                children=[
                    dbc.Alert(
                        [
                            html.I(className="fas fa-info-circle me-2"),
                            "No charts added yet. Select a predefined chart or create a custom chart.",
                        ],
                        color="info",
                        className="text-center",
                    ),
                ]
            )

        rendered = []

        for chart_id in chart_ids:
            chart = chart_registry.get(chart_id)

            # If not in registry, try to create from chart_configs store
            # Register in active charts for caching during this session
            if not chart:
                try:
                    config_dict = chart_configs[chart_id]
                    chart_config = Chart.from_dict(config_dict)
                    chart = ChartFactory.create_chart(chart_config, data_service)
                    chart.graph_id = chart_id
                    chart_registry.register_active(chart)
                except Exception as e:
                    rendered.append(
                        dbc.Alert(
                            [
                                html.I(className="fas fa-exclamation-circle me-2"),
                                f"Error loading chart '{chart_id}': {str(e)}",
                            ],
                            color="danger",
                        )
                    )
                    continue

            try:
                chart_component = chart.render(filter_values or {})
                is_editable = chart.config.is_editable if chart.config else False
                rendered.append(create_chart_wrapper(chart_id, chart.title, chart_component, is_editable))
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

        return dict(children=rendered)


def _register_update_all(dash_app: "Dash", collection_name: CollectionName) -> None:
    @dash_app.callback(
        output=dict(trigger=Output(f"{collection_name}-render-trigger", "data")),
        inputs=dict(n_clicks=Input(f"{collection_name}-update-all-btn", "n_clicks")),
        state=dict(current_trigger=State(f"{collection_name}-render-trigger", "data")),
        prevent_initial_call=True,
    )
    def trigger_update_all(n_clicks, current_trigger):
        """
        When user clicks the update-all-btn we update all charts.

        The `{collection_name}-render-trigger` triggers the render_charts function above.
        """
        return dict(trigger=(current_trigger or 0) + 1)
