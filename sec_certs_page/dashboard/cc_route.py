"""Registers dashboard page route for Common Criteria (CC) dashboard."""

from typing import Union

import dash
from dash import dcc, html
from dash.dependencies import Input, Output, State
from dash.development.base_component import Component

from ..common.dash.base import Dash
from .graphs.registry import GraphRegistry


def register_pages(app: Dash, cc_graph_registry: GraphRegistry) -> None:
    """
    Register CC dashboard page with Dash and its interactive callbacks.

    Args:
        app: The main Dash application instance for callback registration.
        cc_graph_registry: The registry containing all available CC graphs.
    """

    def layout() -> html.Div:
        return html.Div(
            children=[
                # Client-side store for active graphs. Initialized with the pie chart.
                dcc.Store(id="cc-active-graphs-store", data=["cc-pie-chart"]),
                html.H1("Common Criteria (CC) Interactive Dashboard"),
                html.P("Data sourced from live MongoDB."),
                html.Hr(),
                # --- UI Controls for adding graphs ---
                html.Div(
                    [
                        dcc.Dropdown(
                            id="cc-graph-selector",
                            options=[{"label": graph.title, "value": graph.id} for graph in cc_graph_registry],
                            placeholder="Select a graph to add...",
                            style={"width": "300px", "display": "inline-block"},
                        ),
                        html.Button("Add Graph", id="cc-add-graph-btn", n_clicks=0, style={"display": "inline-block"}),
                    ],
                    style={"marginBottom": "20px"},
                ),
                # --- Container where dynamic graphs will be rendered ---
                html.Div(id="cc-graph-container"),
            ]
        )

    dash.register_page(
        __name__,
        path="/cc",
        title="CC Dashboard",
        name="CC Dashboard",
        layout=layout,
    )

    @app.callback(
        Output("cc-active-graphs-store", "data"),
        Input("cc-add-graph-btn", "n_clicks"),
        State("cc-graph-selector", "value"),
        State("cc-active-graphs-store", "data"),
        prevent_initial_call=True,
    )
    def add_graph_to_store(n_clicks: int, selected_graph_id: str, active_graphs: list[str]) -> list[str]:
        """Adds a selected graph's ID to the client-side store if it's not already there."""
        if selected_graph_id and selected_graph_id not in active_graphs:
            return active_graphs + [selected_graph_id]
        return active_graphs

    @app.callback(
        Output("cc-graph-container", "children"),
        Input("cc-active-graphs-store", "data"),
    )
    def render_graphs_from_store(active_graph_ids: list[str]) -> list[Component]:
        """Renders the graph components into the layout based on the IDs in the store."""
        if not active_graph_ids:
            return [html.Div([html.P("No graphs selected. Use the dropdown above to add a graph.")])]

        rendered_graphs: list[Component] = []
        for graph_id in active_graph_ids:
            try:
                graph_component = cc_graph_registry[graph_id].render()
                if graph_component:
                    # Wrap in Div if not already a Div to ensure consistent container structure
                    if not isinstance(graph_component, html.Div):
                        rendered_graphs.append(html.Div([graph_component]))
                    else:
                        rendered_graphs.append(graph_component)
            except KeyError:
                rendered_graphs.append(html.Div([html.P(f"Error: Graph '{graph_id}' not found in registry.")]))
        return rendered_graphs
