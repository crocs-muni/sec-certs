"""
Dash callback registration for the dashboard system.

This module contains all callback registration functions for:
- Filter option loading (populate dropdowns from database)
- Filter value collection (sync filter state to stores)
- Chart management (add/remove charts)
- Chart rendering (render charts with current filters)
- Dashboard-level update functionality
- Save/update button state management
"""

from typing import TYPE_CHECKING

from dash import ALL, MATCH, ctx, html
from dash.dependencies import Input, Output, State
from dash.development.base_component import Component

from .filters.component_factory import DashFilterFactory
from .types.common import CollectionName
from .types.filter import FilterComponentType

if TYPE_CHECKING:
    from ..common.dash.base import Dash
    from .chart.registry import ChartRegistry
    from .data import DataService


def register_all_callbacks(
    app: "Dash",
    data_service: "DataService",
    filter_factories: dict[CollectionName, DashFilterFactory],
    chart_registries: dict[CollectionName, "ChartRegistry"],
) -> None:
    """
    Register all dashboard callbacks.

    :param app: Dash application instance
    :param data_service: Data service for database queries
    :param filter_factories: Filter factories by dataset type
    :param chart_registries: Chart registries by dataset type
    """
    # Register callbacks for each dataset type
    for dataset_type in CollectionName:
        filter_factory = filter_factories[dataset_type]
        chart_registry = chart_registries[dataset_type]
        prefix = dataset_type.value

        _register_filter_option_callbacks(app, filter_factory, data_service)
        _register_filter_store_callback(app, prefix, filter_factory)
        _register_chart_management_callbacks(app, prefix)
        _register_chart_rendering_callback(app, prefix, chart_registry)
        _register_update_all_callback(app, prefix)
        _register_button_state_callbacks(app, prefix)

    # Register pattern-matching callbacks (global, work across all pages)
    _register_pattern_matching_callbacks(app, chart_registries)


def _register_filter_option_callbacks(
    app: "Dash",
    filter_factory: DashFilterFactory,
    data_service: "DataService",
) -> None:
    """Register callbacks to populate filter dropdown options from database."""

    for filter_id, filter_spec in filter_factory.registry.get_all_filters().items():
        if filter_spec.component_params.component_type not in (
            FilterComponentType.DROPDOWN,
            FilterComponentType.MULTI_DROPDOWN,
        ):
            continue

        @app.callback(
            Output(filter_id, "options"),
            Input(filter_id, "id"),
            prevent_initial_call=False,
        )
        def load_options(
            _,  # dummy input value
            spec=filter_spec,
            factory=filter_factory,
            ds=data_service,
        ):
            """Load distinct values from database for this filter."""
            try:
                return ds.get_distinct_values_with_labels(
                    field=spec.database_field,
                    dataset_type=factory.dataset_type,
                )
            except Exception as e:
                print(f"Error loading options for {spec.id}: {e}")
                return []


def _register_filter_store_callback(
    app: "Dash",
    prefix: str,
    filter_factory: DashFilterFactory,
) -> None:
    """Register callback to collect all filter values into a store."""

    filter_inputs = filter_factory.create_callback_inputs()

    if not filter_inputs:
        return

    @app.callback(
        Output(f"{prefix}-filter-store", "data"),
        filter_inputs,
        prevent_initial_call=False,
    )
    def update_filter_store(*filter_values) -> dict:
        """Collect filter values into store for charts to consume."""
        return filter_factory.collect_filter_values(*filter_values)


def _register_chart_management_callbacks(app: "Dash", prefix: str) -> None:
    """Register callbacks for adding/removing charts from active list."""

    @app.callback(
        Output(f"{prefix}-active-charts-store", "data"),
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
        """Add or remove charts from the active list."""
        if current_charts is None:
            current_charts = []

        triggered_id = ctx.triggered_id

        # Handle add chart
        if triggered_id == f"{prefix}-add-chart-btn":
            if selected_chart_id and selected_chart_id not in current_charts:
                current_charts.append(selected_chart_id)

        # Handle remove chart (pattern-matching)
        elif isinstance(triggered_id, dict) and triggered_id.get("type") == "remove-chart":
            chart_to_remove = triggered_id.get("index")
            if chart_to_remove in current_charts:
                current_charts.remove(chart_to_remove)

        return current_charts


def _register_chart_rendering_callback(
    app: "Dash",
    prefix: str,
    chart_registry: "ChartRegistry",
) -> None:
    """Register callback to render all active charts."""

    @app.callback(
        Output(f"{prefix}-chart-container", "children"),
        Input(f"{prefix}-active-charts-store", "data"),
        Input(f"{prefix}-render-trigger", "data"),  # Triggered by update buttons
        State(f"{prefix}-filter-store", "data"),
        prevent_initial_call=False,
    )
    def render_charts(
        chart_ids: list | None,
        render_trigger: int | None,
        filter_values: dict | None,
    ) -> list[Component]:
        """Render all active charts with current filter values."""
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
                rendered.append(_create_chart_wrapper(chart_id, chart.title, chart_component))

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


def _create_chart_wrapper(chart_id: str, title: str, chart_component: Component) -> html.Div:
    """Create a wrapper div for a chart with controls."""
    return html.Div(
        id={"type": "chart-wrapper", "index": chart_id},
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


def _register_update_all_callback(app: "Dash", prefix: str) -> None:
    """Register callback for the 'Update All Charts' button."""

    @app.callback(
        Output(f"{prefix}-render-trigger", "data"),
        Input(f"{prefix}-update-all-btn", "n_clicks"),
        State(f"{prefix}-render-trigger", "data"),
        prevent_initial_call=True,
    )
    def trigger_update_all(n_clicks: int, current_trigger: int | None) -> int:
        """Increment render trigger to force all charts to re-render."""
        return (current_trigger or 0) + 1


def _register_button_state_callbacks(app: "Dash", prefix: str) -> None:
    """Register callbacks to enable/disable update and save buttons based on filter state."""

    @app.callback(
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
        """
        Enable update/save buttons only when there are active filters with values.

        :returns: Tuple of (update_btn_disabled, save_btn_disabled)
        """
        has_active_filters = bool(filter_values and len(filter_values) > 0)
        has_charts = bool(active_charts and len(active_charts) > 0)

        # Update button: enabled if there are charts (filters optional for refresh)
        update_disabled = not has_charts

        # Save button: enabled only if there are both charts AND active filters
        save_disabled = not (has_charts and has_active_filters)

        return update_disabled, save_disabled


def _register_pattern_matching_callbacks(
    app: "Dash",
    chart_registries: dict[CollectionName, "ChartRegistry"],
) -> None:
    """Register pattern-matching callbacks for individual chart interactions."""
    from dash import no_update

    @app.callback(
        Output({"type": "chart-content", "index": MATCH}, "children"),
        Input({"type": "chart-refresh", "index": MATCH}, "n_clicks"),
        State({"type": "chart-wrapper", "index": MATCH}, "id"),
        prevent_initial_call=True,
    )
    def refresh_single_chart(n_clicks: int, wrapper_id: dict | None):
        """Refresh a single chart when its refresh button is clicked."""
        if not n_clicks:
            return no_update

        chart_id = wrapper_id.get("index") if wrapper_id else None
        if not chart_id:
            return no_update

        # Find the chart in any registry
        for registry in chart_registries.values():
            chart = registry.get(chart_id)
            if chart:
                try:
                    return chart.render()
                except Exception as e:
                    return html.P(f"Error refreshing chart: {str(e)}", style={"color": "red"})

        return html.P(f"Chart '{chart_id}' not found.", style={"color": "red"})
