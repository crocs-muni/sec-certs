# sec_certs_page/dashboard/cc_route.py
"""Registers dashboard page route for Common Criteria (CC) dashboard."""

import dash
from dash import dcc, html
from dash.dependencies import Input, Output, State
from dash.development.base_component import Component

from ..common.dash.base import Dash
from .charts.registry import ChartRegistry
from .filters.registry import FilterRegistry


def register_pages(
    app: Dash, cc_graph_registry: ChartRegistry, cc_filter_registry: FilterRegistry, filter_factory=None
) -> None:
    """
    Register CC dashboard page with Dash and its interactive callbacks.

    :param app: The main Dash application instance for callback registration.
    :type app: Dash
    :param cc_graph_registry: The registry containing all available CC graphs.
    :type cc_graph_registry: GraphRegistry
    :param cc_filter_registry: The registry containing all available CC filters.
    :type cc_filter_registry: FilterRegistry
    :param filter_factory: Factory for creating filters on-demand
    """

    # Track if filters have been initialized
    filters_initialized = False

    def layout(**kwargs) -> html.Div:
        """Layout with basic graph controls."""
        nonlocal filters_initialized

        # Create filters on first layout render (true lazy loading!)
        if filter_factory and not filters_initialized:
            print("🚀 First visit to /dashboard/cc - loading data and creating filters...")
            try:
                priority_metadata = filter_factory.get_priority_filters_for_dataset("cc")
                print(f"Got {len(priority_metadata)} priority metadata items")

                for meta in priority_metadata:
                    if meta.filter_type.value in ["dropdown", "text_search"]:
                        filter_id = f"cc-{meta.name}-filter"
                        try:
                            filter_instance = filter_factory.create_filter(meta, filter_id)
                            if filter_instance:
                                cc_filter_registry.register(filter_instance)
                                print(f"  ✓ Registered filter: {filter_id}")
                        except Exception as e:
                            print(f"  ERROR creating filter {filter_id}: {e}")

                filters_initialized = True
                print(f"✓ Created {len(cc_filter_registry)} filters on first page visit")
            except Exception as e:
                print(f"ERROR creating filters: {e}")
                import traceback

                traceback.print_exc()

        print(
            f"CC Dashboard layout() called - {len(cc_filter_registry)} filters, {len(list(cc_graph_registry))} charts"
        )

        # Render filters directly in layout
        filter_components: list[Component] = [html.H3("Filters")]
        if cc_filter_registry:
            for filter_instance in cc_filter_registry:
                try:
                    rendered = filter_instance.render("cc")
                    filter_components.append(html.Div(rendered, style={"marginBottom": "10px"}))
                except Exception as e:
                    print(f"ERROR rendering filter {filter_instance.id}: {e}")
                    filter_components.append(
                        html.P(f"Error rendering {filter_instance.id}: {e}", style={"color": "red"})
                    )
        else:
            filter_components.append(html.P("No filters available yet.", style={"color": "gray"}))

        try:
            return html.Div(
                children=[
                    # Client-side store for active graphs
                    dcc.Store(id="cc-filter-store", data={}),
                    dcc.Store(id="cc-active-graphs-store", data=[]),
                    html.H1("Common Criteria (CC) Interactive Dashboard"),
                    html.P("Interactive dashboard for CC dataset analysis."),
                    html.Hr(),
                    # Filter Controls Section
                    html.Div(
                        id="cc-filters-container",
                        children=filter_components,
                        style={"marginBottom": "20px", "padding": "10px", "border": "1px solid #ddd"},
                    ),
                    # Graph Controls
                    html.Div(
                        [
                            html.H3("Graph Controls"),
                            dcc.Dropdown(
                                id="cc-graph-selector",
                                options=[{"label": graph.title, "value": graph.id} for graph in cc_graph_registry],
                                placeholder="Select a graph to add...",
                                style={"width": "300px", "display": "inline-block"},
                            ),
                            html.Button(
                                "Add Graph",
                                id="cc-add-graph-btn",
                                n_clicks=0,
                                style={"display": "inline-block", "marginLeft": "10px"},
                            ),
                        ],
                        style={"marginBottom": "20px"},
                    ),
                    # Graph Container
                    html.Div(id="cc-graph-container"),
                    # Status
                    html.Hr(),
                    html.P(
                        f"Registry status: {len(list(cc_graph_registry)) if cc_graph_registry else 0} charts available",
                        style={"color": "gray", "fontSize": "small"},
                    ),
                ]
            )
        except Exception as e:
            print(f"ERROR in CC dashboard layout: {e}")
            import traceback

            traceback.print_exc()
            return html.Div(
                [
                    html.H1("CC Dashboard"),
                    html.P(f"Layout error: {str(e)}", style={"color": "red"}),
                    html.P("This is a fallback layout."),
                ]
            )

    print("Registering CC dashboard page at path=/cc")
    dash.register_page(
        "cc_dashboard",
        path="/cc",
        title="CC Dashboard",
        name="CC Dashboard",
        layout=layout,
    )
    print("✓ CC dashboard page registered successfully")

    # Register callbacks for all charts in the registry
    try:
        for chart in cc_graph_registry:
            if hasattr(chart, "register_callback"):
                chart.register_callback(app)
        print(f"Successfully registered callbacks for {len(list(cc_graph_registry))} charts")
    except Exception as e:
        print(f"Warning: Could not register chart callbacks: {e}")

    # NOTE: Filter store callback removed - will be added when filters are integrated with charts
    # For now, filters are just UI components without backend filtering logic

    # Add chart accumulation callbacks using Store pattern
    @app.callback(
        Output("cc-active-graphs-store", "data"),
        Input("cc-add-graph-btn", "n_clicks"),
        State("cc-graph-selector", "value"),
        State("cc-active-graphs-store", "data"),
        prevent_initial_call=True,
    )
    def add_graph_to_store(n_clicks: int, selected_graph_id: str, current_graphs: list) -> list:
        """Adds the selected graph ID to the store."""
        if not selected_graph_id:
            return current_graphs or []

        # Initialize current_graphs if None
        if current_graphs is None:
            current_graphs = []

        # Add graph ID if not already in the list
        if selected_graph_id not in current_graphs:
            current_graphs.append(selected_graph_id)

        return current_graphs

    @app.callback(
        Output("cc-graph-container", "children"),
        Input("cc-active-graphs-store", "data"),
        prevent_initial_call=False,
    )
    def render_all_graphs(active_graph_ids: list) -> list[Component]:
        """Renders all graphs stored in the active graphs list."""
        if not active_graph_ids:
            return [html.P("No graphs added yet. Select a graph and click 'Add Graph' to start.")]

        try:
            rendered_graphs = []

            for graph_id in active_graph_ids:
                # Get the chart from registry
                chart = None
                for c in cc_graph_registry:
                    if c.id == graph_id:
                        chart = c
                        break

                if not chart:
                    rendered_graphs.append(
                        html.Div(
                            [html.P(f"Error: Chart '{graph_id}' not found in registry.", style={"color": "red"})],
                            style={"border": "1px solid #ddd", "padding": "10px", "marginBottom": "10px"},
                        )
                    )
                    continue

                # FIXED: Render the actual chart component
                try:
                    chart_component = chart.render()

                    rendered_graphs.append(
                        html.Div(
                            [
                                html.Div(
                                    [
                                        html.H4(f"Chart: {chart.title}", style={"display": "inline-block"}),
                                        html.Button(
                                            "×",
                                            id={"type": "remove-chart", "index": graph_id},
                                            style={
                                                "float": "right",
                                                "background": "red",
                                                "color": "white",
                                                "border": "none",
                                                "borderRadius": "50%",
                                                "width": "25px",
                                                "height": "25px",
                                            },
                                        ),
                                    ],
                                    style={"marginBottom": "10px"},
                                ),
                                chart_component,
                            ],
                            style={"border": "1px solid #ddd", "padding": "10px", "marginBottom": "10px"},
                        )
                    )
                except Exception as render_error:
                    rendered_graphs.append(
                        html.Div(
                            [
                                html.H4(f"Chart: {chart.title}"),
                                html.P(f"Error rendering chart: {str(render_error)}", style={"color": "red"}),
                                html.P(f"Chart ID: {chart.id}"),
                            ],
                            style={"border": "1px solid #ddd", "padding": "10px", "marginBottom": "10px"},
                        )
                    )

            return rendered_graphs

        except Exception as e:
            return [html.P(f"Error rendering graphs: {str(e)}", style={"color": "red"})]
