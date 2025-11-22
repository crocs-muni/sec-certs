"""
Dashboard page registration.

This module registers Dash pages for each dataset type.
All class instantiation and callback registration is handled in __init__.py.
"""

import dash
from dash import dcc, html

from .chart.registry import ChartRegistry
from .filters.component_factory import DashFilterFactory
from .types.common import CollectionName


def register_pages(
    filter_factories: dict[CollectionName, DashFilterFactory],
    chart_registries: dict[CollectionName, ChartRegistry],
) -> None:
    """
    Register all dashboard pages with Dash.

    Creates separate pages for each dataset type (CC, FIPS) with their
    respective filters and chart options.

    :param filter_factories: Filter factories by dataset type
    :param chart_registries: Chart registries by dataset type
    """
    for dataset_type in CollectionName:
        filter_factory = filter_factories[dataset_type]
        chart_registry = chart_registries[dataset_type]
        _register_dataset_page(dataset_type, filter_factory, chart_registry)


def _register_dataset_page(
    dataset_type: CollectionName,
    filter_factory: DashFilterFactory,
    chart_registry: ChartRegistry,
) -> None:
    """
    Register a single dataset-specific dashboard page.

    :param dataset_type: Dataset type for this page
    :param filter_factory: Filter factory for this dataset
    :param chart_registry: Chart registry for this dataset
    """
    page_path = f"/{dataset_type.value}"
    page_name = f"{dataset_type.value}_dashboard"
    prefix = dataset_type.value

    def layout(**kwargs) -> html.Div:
        """Create dashboard layout for this dataset type."""
        # Build chart selector options
        chart_options: list = [{"label": chart.title, "value": chart.id} for chart in chart_registry]

        return html.Div(
            [
                # Stores for state management
                dcc.Store(id=f"{prefix}-filter-store", data={}),
                dcc.Store(id=f"{prefix}-active-charts-store", data=[]),
                dcc.Store(id=f"{prefix}-render-trigger", data=0),  # Triggers chart re-renders
                # Header
                html.H1(f"{dataset_type.value.upper()} Interactive Dashboard"),
                html.P(f"Interactive dashboard for {dataset_type.value} dataset analysis."),
                html.Hr(),
                # Chart Controls
                html.Div(
                    [
                        html.H3("Chart Controls"),
                        html.Div(
                            [
                                dcc.Dropdown(
                                    id=f"{prefix}-chart-selector",
                                    options=chart_options,
                                    placeholder="Select a chart to add...",
                                    style={"width": "300px", "display": "inline-block"},
                                ),
                                html.Button(
                                    "Add Chart",
                                    id=f"{prefix}-add-chart-btn",
                                    n_clicks=0,
                                    style={"display": "inline-block", "marginLeft": "10px"},
                                ),
                            ],
                            style={"marginBottom": "10px"},
                        ),
                        html.Div(
                            [
                                html.Button(
                                    "🔄 Update All Charts",
                                    id=f"{prefix}-update-all-btn",
                                    n_clicks=0,
                                    disabled=True,  # Enabled by callback when charts exist
                                    style={
                                        "marginRight": "10px",
                                        "padding": "8px 16px",
                                        "backgroundColor": "#4CAF50",
                                        "color": "white",
                                        "border": "none",
                                        "borderRadius": "4px",
                                        "cursor": "pointer",
                                    },
                                ),
                                html.Button(
                                    "💾 Save Dashboard",
                                    id=f"{prefix}-save-dashboard-btn",
                                    n_clicks=0,
                                    disabled=True,  # Enabled by callback when filters are set
                                    style={
                                        "padding": "8px 16px",
                                        "backgroundColor": "#2196F3",
                                        "color": "white",
                                        "border": "none",
                                        "borderRadius": "4px",
                                        "cursor": "pointer",
                                    },
                                ),
                            ],
                        ),
                    ],
                    style={"marginBottom": "20px"},
                ),
                # Chart Container
                html.Div(id=f"{prefix}-chart-container"),
                # Status
                html.Hr(),
                html.P(
                    f"Available: {len(list(chart_registry))} charts, "
                    f"{len(filter_factory.get_filter_ids())} filters",
                    style={"color": "gray", "fontSize": "small"},
                ),
            ]
        )

    # Register the page
    dash.register_page(
        page_name,
        path=page_path,
        title=f"{dataset_type.value.upper()} Dashboard",
        name=f"{dataset_type.value.upper()} Dashboard",
        layout=layout,
    )

    print(f"✓ Registered {page_name} at {page_path}")
