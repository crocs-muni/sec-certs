"""Common utilities for dashboard collection pages."""

import dash_bootstrap_components as dbc
from dash import dcc, html

from ... import DASHBOARD_URL_BASE_PATHNAME
from ..types.chart import AvailableChartTypes
from ..types.common import CollectionName
from ..types.filter import AggregationType

# Data type to available aggregations mapping
DATA_TYPE_AGGREGATIONS: dict[str, list[AggregationType]] = {
    # Numeric types support all aggregations
    "int": [AggregationType.COUNT, AggregationType.SUM, AggregationType.AVG, AggregationType.MIN, AggregationType.MAX],
    "float": [
        AggregationType.COUNT,
        AggregationType.SUM,
        AggregationType.AVG,
        AggregationType.MIN,
        AggregationType.MAX,
    ],
    "number": [
        AggregationType.COUNT,
        AggregationType.SUM,
        AggregationType.AVG,
        AggregationType.MIN,
        AggregationType.MAX,
    ],
    "numeric": [
        AggregationType.COUNT,
        AggregationType.SUM,
        AggregationType.AVG,
        AggregationType.MIN,
        AggregationType.MAX,
    ],
    # String types only support COUNT
    "str": [AggregationType.COUNT],
    "string": [AggregationType.COUNT],
    # Date types support COUNT, MIN, MAX
    "date": [AggregationType.COUNT, AggregationType.MIN, AggregationType.MAX],
    "datetime": [AggregationType.COUNT, AggregationType.MIN, AggregationType.MAX],
    # Boolean only supports COUNT
    "bool": [AggregationType.COUNT],
    "boolean": [AggregationType.COUNT],
}

# Default aggregations for unknown types
DEFAULT_AGGREGATIONS = [AggregationType.COUNT]


def get_aggregations_for_type(data_type: str) -> list[dict[str, str]]:
    """
    Get available aggregation options based on data type.

    :param data_type: The data type string (e.g., "int", "str", "date")
    :return: List of dicts with 'label' and 'value' for dropdown options
    """
    aggregations = DATA_TYPE_AGGREGATIONS.get(data_type.lower(), DEFAULT_AGGREGATIONS)
    return [{"label": agg.value.upper(), "value": agg.value} for agg in aggregations]


def create_collection_page_layout(collection: CollectionName, title: str) -> html.Div:
    """
    Create the complete layout for a collection dashboard page.

    :param collection: The collection enum value
    :param title: The page title to display
    :return: Complete page layout
    """
    prefix = collection.value

    return html.Div(
        children=[
            # State stores
            *create_page_stores(prefix),
            # Page header
            dbc.Row(
                className="mb-4",
                children=[
                    dbc.Col(
                        children=[
                            html.H1(title, className="mb-2"),
                            dcc.Link(
                                [html.I(className="fas fa-arrow-left me-2"), "Back to Dashboard Home"],
                                href=DASHBOARD_URL_BASE_PATHNAME,
                                className="text-muted text-decoration-none",
                            ),
                        ],
                    ),
                ],
            ),
            # Dashboard management section
            dbc.Card(
                className="mb-4",
                children=[
                    dbc.CardBody(
                        children=[
                            create_dashboard_management_buttons(prefix),
                        ],
                    ),
                ],
            ),
            # Empty state
            create_empty_state(prefix),
            # Dashboard content
            create_dashboard_content(prefix),
        ],
    )


def create_page_stores(collection_name: str) -> list:
    """
    Create the common dcc.Store components used by collection pages.

    :param collection_name: The collection name (e.g., "cc", "fips")
    :return: List of dcc.Store components
    """
    return [
        dcc.Store(id=f"{collection_name}-collection-name", data=collection_name),
        dcc.Store(id=f"{collection_name}-current-dashboard-id", data=None),
        dcc.Store(id=f"{collection_name}-active-charts-store", data=[]),
        dcc.Store(id=f"{collection_name}-filter-store", data={}),
        dcc.Store(id=f"{collection_name}-render-trigger", data=0),
        dcc.Store(id=f"{collection_name}-dashboard-loaded", data=False),
        # Store for available fields metadata (populated from FilterFactory)
        # Format: [{"label": "Category", "value": "category", "data_type": "str"}, ...]
        dcc.Store(id=f"{collection_name}-available-fields", data=[]),
        # Store for filter specifications metadata (for chart modal filter options)
        # Format: [{"id": "cc-category-filter", "label": "Category", "field": "category", ...}, ...]
        dcc.Store(id=f"{collection_name}-filter-specs", data=[]),
        # Store for tracking which chart is being edited (None = create mode, chart_id = edit mode)
        dcc.Store(id=f"{collection_name}-edit-chart-id", data=None),
        # Store for chart configurations (chart_id -> serialized Chart config)
        # Used to populate edit modal without database queries
        dcc.Store(id=f"{collection_name}-chart-configs-store", data={}),
    ]


def create_dashboard_management_buttons(collection_name: str) -> dbc.Row:
    """
    Create the dashboard management buttons (Create New, Load Predefined).

    :param collection_name: The collection_name for component IDs
    :return: Row containing the action buttons
    """
    return dbc.Row(
        className="g-3 align-items-end",
        children=[
            # Dashboard selector
            dbc.Col(
                width=12,
                lg=4,
                children=[
                    dbc.Label(
                        "Select Dashboard", html_for=f"{collection_name}-dashboard-selector", className="fw-bold"
                    ),
                    dcc.Dropdown(
                        id=f"{collection_name}-dashboard-selector",
                        options=[],
                        placeholder="Select a saved dashboard...",
                        clearable=True,
                        className="dash-bootstrap",
                    ),
                ],
            ),
            # Create new button
            dbc.Col(
                width="auto",
                children=[
                    dbc.Button(
                        [html.I(className="fas fa-plus me-2"), "Create New Dashboard"],
                        id=f"{collection_name}-create-dashboard-btn",
                        n_clicks=0,
                        color="success",
                        className="w-100",
                    ),
                ],
            ),
        ],
    )


def create_empty_state(collection_name: str) -> html.Div:
    """
    Create the empty state display when no dashboard is selected.

    :param collection_name: The collection_name for component IDs
    :return: Div with empty state content
    """
    return html.Div(
        id=f"{collection_name}-empty-state",
        style={"display": "block"},
        children=[
            dbc.Card(
                className="text-center border-2 border-dashed",
                children=[
                    dbc.CardBody(
                        className="py-5",
                        children=[
                            html.I(className="fas fa-chart-line fa-3x text-muted mb-3"),
                            html.H3("No Dashboard Selected", className="text-muted"),
                            html.P(
                                "Create a new dashboard or select an existing one from the dropdown above.",
                                className="text-muted lead",
                            ),
                        ],
                    ),
                ],
            ),
        ],
    )


def create_chart_creation_modal(collection_name: str) -> dbc.Modal:
    """
    Create the modal for custom chart creation.

    The modal allows users to:
    - Select chart type (bar, line, pie, etc.)
    - Choose X-axis field (group by)
    - Choose aggregation type (count, sum, avg, min, max)
    - Choose Y-axis field (for non-count aggregations)

    :param collection_name: The collection_name for component IDs
    :return: Modal component for chart creation
    """
    chart_type_options = [
        {"label": ct.value.replace("_", " ").title(), "value": ct.value} for ct in AvailableChartTypes
    ]

    aggregation_options = [{"label": agg.value.upper(), "value": agg.value} for agg in AggregationType]

    return dbc.Modal(
        id=f"{collection_name}-create-chart-modal",
        is_open=False,
        size="lg",
        centered=True,
        children=[
            dbc.ModalHeader(
                dbc.ModalTitle(
                    id=f"{collection_name}-modal-title",
                    children=[html.I(className="fas fa-chart-bar me-2"), "Create Custom Chart"],
                ),
                close_button=True,
            ),
            dbc.ModalBody(
                children=[
                    # Chart title
                    dbc.Row(
                        className="mb-3",
                        children=[
                            dbc.Col(
                                width=12,
                                children=[
                                    dbc.Label(
                                        "Chart Title",
                                        html_for=f"{collection_name}-modal-chart-title",
                                        className="fw-bold",
                                    ),
                                    dbc.Input(
                                        id=f"{collection_name}-modal-chart-title",
                                        type="text",
                                        placeholder="Enter chart title...",
                                        value="",
                                    ),
                                ],
                            ),
                        ],
                    ),
                    # Chart type selection
                    dbc.Row(
                        className="mb-3",
                        children=[
                            dbc.Col(
                                width=12,
                                md=6,
                                children=[
                                    dbc.Label(
                                        "Chart Type",
                                        html_for=f"{collection_name}-modal-chart-type",
                                        className="fw-bold",
                                    ),
                                    dcc.Dropdown(
                                        id=f"{collection_name}-modal-chart-type",
                                        options=chart_type_options,
                                        value=AvailableChartTypes.BAR.value,
                                        clearable=False,
                                        className="dash-bootstrap",
                                    ),
                                    html.Div(
                                        id=f"{collection_name}-chart-type-help",
                                        className="mt-1",
                                    ),
                                ],
                            ),
                        ],
                    ),
                    html.Hr(),
                    # X-Axis configuration
                    html.H5([html.I(className="fas fa-arrows-alt-h me-2"), "X-Axis (Group By)"], className="mb-3"),
                    dbc.Row(
                        className="mb-3",
                        children=[
                            dbc.Col(
                                width=12,
                                md=6,
                                children=[
                                    dbc.Label(
                                        "Primary Field",
                                        html_for=f"{collection_name}-modal-x-field",
                                        className="fw-bold",
                                    ),
                                    dcc.Dropdown(
                                        id=f"{collection_name}-modal-x-field",
                                        options=[],  # Populated dynamically from FilterFactory
                                        placeholder="Select field to group by...",
                                        className="dash-bootstrap",
                                    ),
                                ],
                            ),
                            dbc.Col(
                                width=12,
                                md=6,
                                children=[
                                    dbc.Label(
                                        "X-Axis Label", html_for=f"{collection_name}-modal-x-label", className="fw-bold"
                                    ),
                                    dbc.Input(
                                        id=f"{collection_name}-modal-x-label",
                                        type="text",
                                        placeholder="X-axis label (optional)",
                                        value="",
                                    ),
                                ],
                            ),
                        ],
                    ),
                    # Secondary grouping (Color By) - Collapsible
                    dbc.Button(
                        [
                            html.I(className="fas fa-chevron-right me-2", id=f"{collection_name}-color-by-icon"),
                            "Secondary Grouping (Color By)",
                        ],
                        id=f"{collection_name}-color-by-toggle",
                        color="link",
                        className="p-0 mb-2 text-decoration-none",
                    ),
                    dbc.Collapse(
                        id=f"{collection_name}-color-by-collapse",
                        is_open=False,
                        children=[
                            dbc.Row(
                                className="mb-3",
                                children=[
                                    dbc.Col(
                                        width=12,
                                        md=6,
                                        children=[
                                            dbc.Label(
                                                "Secondary Field (Color By)",
                                                html_for=f"{collection_name}-modal-color-field",
                                                className="fw-bold",
                                            ),
                                            dcc.Dropdown(
                                                id=f"{collection_name}-modal-color-field",
                                                options=[],  # Populated dynamically
                                                placeholder="Optional: Select field for color grouping...",
                                                className="dash-bootstrap",
                                                clearable=True,
                                            ),
                                            dbc.FormText(
                                                "Creates grouped/stacked bars or colored segments.",
                                                className="text-muted",
                                            ),
                                        ],
                                    ),
                                ],
                            ),
                        ],
                    ),
                    html.Hr(),
                    # Y-Axis configuration
                    html.H5([html.I(className="fas fa-arrows-alt-v me-2"), "Y-Axis (Measure)"], className="mb-3"),
                    dbc.Row(
                        className="mb-3",
                        children=[
                            dbc.Col(
                                width=12,
                                md=6,
                                children=[
                                    dbc.Label(
                                        "Aggregation",
                                        html_for=f"{collection_name}-modal-aggregation",
                                        className="fw-bold",
                                    ),
                                    dcc.Dropdown(
                                        id=f"{collection_name}-modal-aggregation",
                                        options=aggregation_options,
                                        value=AggregationType.COUNT.value,
                                        clearable=False,
                                        className="dash-bootstrap",
                                    ),
                                    dbc.FormText(
                                        "COUNT counts rows. Other aggregations require a numeric field.",
                                        className="text-muted",
                                    ),
                                ],
                            ),
                            dbc.Col(
                                width=12,
                                md=6,
                                children=[
                                    dbc.Label(
                                        "Field to Aggregate",
                                        html_for=f"{collection_name}-modal-y-field",
                                        className="fw-bold",
                                    ),
                                    dcc.Dropdown(
                                        id=f"{collection_name}-modal-y-field",
                                        options=[],  # Populated dynamically (numeric fields only)
                                        placeholder="Select field (for SUM/AVG/MIN/MAX)...",
                                        disabled=True,  # Enabled when aggregation != COUNT
                                        className="dash-bootstrap",
                                    ),
                                    dbc.FormText(
                                        id=f"{collection_name}-modal-y-field-help",
                                        children="Not required for COUNT aggregation.",
                                        className="text-muted",
                                    ),
                                ],
                            ),
                        ],
                    ),
                    dbc.Row(
                        className="mb-3",
                        children=[
                            dbc.Col(
                                width=12,
                                md=6,
                                children=[
                                    dbc.Label(
                                        "Y-Axis Label", html_for=f"{collection_name}-modal-y-label", className="fw-bold"
                                    ),
                                    dbc.Input(
                                        id=f"{collection_name}-modal-y-label",
                                        type="text",
                                        placeholder="Y-axis label (optional)",
                                        value="",
                                    ),
                                ],
                            ),
                        ],
                    ),
                    html.Hr(),
                    # Chart-specific filters section
                    html.H5([html.I(className="fas fa-filter me-2"), "Chart Filters"], className="mb-3"),
                    html.P(
                        "Configure filters to limit the data shown in this chart. "
                        "Leave empty to include all data (or use dashboard-level filters).",
                        className="text-muted small mb-3",
                    ),
                    # Dynamic filter container - populated by callback based on available fields
                    html.Div(
                        id=f"{collection_name}-modal-filters-container",
                        children=[],  # Will be populated dynamically
                    ),
                    html.Hr(),
                    # Display options
                    html.H5([html.I(className="fas fa-cog me-2"), "Display Options"], className="mb-3"),
                    dbc.Row(
                        children=[
                            dbc.Col(
                                width="auto",
                                children=[
                                    dbc.Checkbox(
                                        id=f"{collection_name}-modal-show-legend",
                                        label="Show Legend",
                                        value=True,
                                    ),
                                ],
                            ),
                            dbc.Col(
                                width="auto",
                                children=[
                                    dbc.Checkbox(
                                        id=f"{collection_name}-modal-show-grid",
                                        label="Show Grid",
                                        value=True,
                                    ),
                                ],
                            ),
                        ],
                    ),
                    # Validation feedback
                    dbc.Alert(
                        id=f"{collection_name}-modal-validation-alert",
                        is_open=False,
                        color="danger",
                        className="mt-3",
                    ),
                ],
            ),
            dbc.ModalFooter(
                children=[
                    dbc.Button(
                        "Cancel",
                        id=f"{collection_name}-modal-cancel-btn",
                        color="secondary",
                        outline=True,
                    ),
                    dbc.Button(
                        id=f"{collection_name}-modal-create-btn",
                        color="success",
                        children=[html.I(className="fas fa-plus me-2"), "Create Chart"],
                    ),
                ],
            ),
        ],
    )


def create_chart_controls(collection_name: str) -> dbc.Card:
    """
    Create the chart selection and addition controls.

    Includes both predefined chart selection and custom chart creation button.

    :param collection_name: The collection_name for component IDs
    :return: Card containing chart controls
    """
    return dbc.Card(
        className="mb-4",
        children=[
            dbc.CardHeader(
                html.H4("Add Charts", className="mb-0"),
            ),
            dbc.CardBody(
                children=[
                    dbc.Row(
                        className="g-4",
                        children=[
                            # Left column: Predefined charts
                            dbc.Col(
                                width=12,
                                lg=6,
                                children=[
                                    html.H5("Predefined Charts", className="text-muted mb-2"),
                                    dbc.Row(
                                        className="g-3 align-items-end",
                                        children=[
                                            dbc.Col(
                                                width=12,
                                                xl=8,
                                                children=[
                                                    dbc.Label(
                                                        "Select Predefined Chart",
                                                        html_for=f"{collection_name}-chart-selector",
                                                        className="fw-bold",
                                                    ),
                                                    dcc.Dropdown(
                                                        id=f"{collection_name}-chart-selector",
                                                        options=[],
                                                        placeholder="Select a predefined chart...",
                                                        className="dash-bootstrap",
                                                    ),
                                                ],
                                            ),
                                            dbc.Col(
                                                width="auto",
                                                children=[
                                                    dbc.Button(
                                                        [html.I(className="fas fa-plus me-2"), "Add Predefined"],
                                                        id=f"{collection_name}-add-chart-btn",
                                                        n_clicks=0,
                                                        color="primary",
                                                    ),
                                                ],
                                            ),
                                        ],
                                    ),
                                ],
                            ),
                            # Right column: Custom chart
                            dbc.Col(
                                width=12,
                                lg=6,
                                children=[
                                    html.H5("Custom Chart", className="text-muted mb-2"),
                                    dbc.Button(
                                        html.I(className="fas fa-plus"),
                                        id=f"{collection_name}-open-create-chart-modal-btn",
                                        n_clicks=0,
                                        color="success",
                                        outline=True,
                                        title="Add Chart",
                                        style={"width": "42px", "height": "42px"},
                                    ),
                                ],
                            ),
                        ],
                    ),
                ],
            ),
        ],
    )


def create_dashboard_action_buttons(collection_name: str) -> dbc.Row:
    """
    Create the dashboard action buttons (Update All, Save).

    :param collection_name: The collection_name for component IDs
    :return: Row containing action buttons
    """
    return dbc.Row(
        className="mb-4 g-2",
        children=[
            dbc.Col(
                width="auto",
                children=[
                    dbc.Button(
                        [html.I(className="fas fa-sync-alt me-2"), "Update All Charts"],
                        id=f"{collection_name}-update-all-btn",
                        n_clicks=0,
                        disabled=True,
                        color="success",
                        outline=True,
                    ),
                ],
            ),
            dbc.Col(
                width="auto",
                children=[
                    dbc.Button(
                        [html.I(className="fas fa-save me-2"), "Save Dashboard"],
                        id=f"{collection_name}-save-dashboard-btn",
                        n_clicks=0,
                        disabled=True,
                        color="primary",
                    ),
                ],
            ),
        ],
    )


def create_dashboard_content(collection_name: str) -> html.Div:
    """
    Create the dashboard content area shown when a dashboard is active.

    :param collection_name: The collection_name for component IDs
    :return: Div containing dashboard content
    """
    return html.Div(
        id=f"{collection_name}-dashboard-content",
        style={"display": "none"},
        children=[
            # Dashboard name input
            dbc.Card(
                className="mb-4",
                children=[
                    dbc.CardBody(
                        children=[
                            dbc.Row(
                                className="align-items-center",
                                children=[
                                    dbc.Col(
                                        width=12,
                                        md=6,
                                        children=[
                                            dbc.Label(
                                                "Dashboard Name",
                                                html_for=f"{collection_name}-dashboard-name-input",
                                                className="fw-bold",
                                            ),
                                            dbc.Input(
                                                id=f"{collection_name}-dashboard-name-input",
                                                type="text",
                                                value="New Dashboard",
                                                className="form-control",
                                            ),
                                        ],
                                    ),
                                ],
                            ),
                        ],
                    ),
                ],
            ),
            # Chart controls
            create_chart_controls(collection_name),
            # Dashboard action buttons
            create_dashboard_action_buttons(collection_name),
            # Chart container
            html.Div(id=f"{collection_name}-chart-container"),
            # Chart creation modal
            create_chart_creation_modal(collection_name),
        ],
    )
