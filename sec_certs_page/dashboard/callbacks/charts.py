from typing import TYPE_CHECKING

import dash_bootstrap_components as dbc
from dash import ALL, MATCH, ctx, html, no_update
from dash.dependencies import Input, Output, State
from dash.development.base_component import Component

from ..chart.chart import Chart
from ..chart.factory import ChartFactory
from ..types.common import CollectionName
from .utils import create_chart_wrapper

if TYPE_CHECKING:
    from ...common.dash.base import Dash
    from ..chart.registry import ChartRegistry
    from ..data import DataService


def register_chart_callbacks(
    dash_app: "Dash",
    prefix: str,
    chart_registry: "ChartRegistry",
    data_service: "DataService",
) -> None:
    _register_chart_management(dash_app, prefix, chart_registry)
    _register_predefined_chart_options(dash_app, prefix, chart_registry)
    _register_chart_rendering(dash_app, prefix, chart_registry, data_service)
    _register_update_all(dash_app, prefix)


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


def _register_chart_management(dash_app: "Dash", prefix: str, chart_registry: "ChartRegistry") -> None:
    @dash_app.callback(
        output=dict(
            chart_configs=Output(f"{prefix}-chart-configs-store", "data", allow_duplicate=True),
        ),
        inputs=dict(
            add_clicks=Input(f"{prefix}-add-chart-btn", "n_clicks"),
            remove_clicks=Input({"type": "remove-chart", "index": ALL}, "n_clicks"),
        ),
        state=dict(
            selected_chart_id=State(f"{prefix}-chart-selector", "value"),
            current_configs=State(f"{prefix}-chart-configs-store", "data"),
        ),
        prevent_initial_call=True,
    )
    def manage_charts(add_clicks, remove_clicks, selected_chart_id, current_configs):
        print(f"[CHART_MGMT] triggered_id: {ctx.triggered_id}")
        print(f"[CHART_MGMT] selected_chart_id: {selected_chart_id}")
        print(f"[CHART_MGMT] remove_clicks: {remove_clicks}")

        if current_configs is None:
            current_configs = {}

        triggered_id = ctx.triggered_id

        if triggered_id == f"{prefix}-add-chart-btn":
            if selected_chart_id and selected_chart_id not in current_configs:
                # Add the chart config (for predefined charts, get from registry)
                predefined = chart_registry.get_predefined(selected_chart_id)
                if predefined and predefined.config:
                    current_configs[selected_chart_id] = predefined.config.to_dict()
                    print(f"[CHART_MGMT] Added predefined chart {selected_chart_id} with config")
                else:
                    print(f"[CHART_MGMT] Chart {selected_chart_id} not found in predefined registry")

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
                print(f"[CHART_MGMT] Removed chart {chart_to_remove}")
            else:
                print("[CHART_MGMT] Ignoring remove trigger (n_clicks=0 or chart not found)")

        print(f"[CHART_MGMT] current_configs keys after: {list(current_configs.keys())}")

        return dict(chart_configs=current_configs)


def _register_predefined_chart_options(
    dash_app: "Dash",
    prefix: str,
    chart_registry: "ChartRegistry",
) -> None:
    @dash_app.callback(
        output=dict(options=Output(f"{prefix}-chart-selector", "options")),
        inputs=dict(style=Input(f"{prefix}-dashboard-content", "style")),
    )
    def populate_predefined_charts(style):
        return dict(options=[{"label": chart.title, "value": chart.id} for chart in chart_registry])


def _register_chart_rendering(
    dash_app: "Dash",
    prefix: str,
    chart_registry: "ChartRegistry",
    data_service: "DataService",
) -> None:
    @dash_app.callback(
        output=dict(children=Output(f"{prefix}-chart-container", "children")),
        inputs=dict(
            render_trigger=Input(f"{prefix}-render-trigger", "data"),
            chart_configs=Input(f"{prefix}-chart-configs-store", "data"),
        ),
        state=dict(filter_values=State(f"{prefix}-filter-store", "data")),
    )
    def render_charts(render_trigger, chart_configs, filter_values):
        # Derive chart IDs from chart_configs keys
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
            if not chart and chart_configs and chart_id in chart_configs:
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
                is_editable = chart.config.name.startswith("custom-") if chart.config else False
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


def _register_update_all(dash_app: "Dash", prefix: str) -> None:
    @dash_app.callback(
        output=dict(trigger=Output(f"{prefix}-render-trigger", "data")),
        inputs=dict(n_clicks=Input(f"{prefix}-update-all-btn", "n_clicks")),
        state=dict(current_trigger=State(f"{prefix}-render-trigger", "data")),
        prevent_initial_call=True,
    )
    def trigger_update_all(n_clicks, current_trigger):
        return dict(trigger=(current_trigger or 0) + 1)
