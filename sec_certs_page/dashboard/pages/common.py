"""Common utilities for dashboard collection pages."""

import dash_bootstrap_components as dbc
from dash import dcc, html

from ... import DASHBOARD_URL_BASE_PATHNAME
from ..dependencies import ComponentID, ComponentIDBuilder, PatternMatchingComponentID
from ..types.chart import ChartType
from ..types.common import CollectionName
from ..types.filter import AggregationType


def create_collection_page_layout(collection_name: CollectionName, title: str) -> html.Div:
    """
    Create the complete layout for a collection dashboard page.

    :param collection_name: The collection enum value
    :param title: The page title to display
    :return: Complete page layout
    """
    cid = ComponentIDBuilder(collection_name)
    return html.Div(
        className="py-3",
        children=[
            # State stores
            *create_page_stores(collection_name),
            # Toast for notifications
            dbc.Toast(
                id=cid(ComponentID.DASHBOARD_TOAST),
                header="Dashboard",
                is_open=False,
                dismissable=True,
                duration=4000,
                icon="info",
                style={"position": "fixed", "top": 66, "right": 10, "width": 350, "zIndex": 1050},
            ),
            # Page header
            dbc.Row(
                className="mb-4",
                children=[
                    dbc.Col(
                        children=[
                            html.H1(title, className="mb-2 fw-bold"),
                            dcc.Link(
                                [html.I(className="fas fa-arrow-left me-2"), "Back to Dashboard Home"],
                                href=DASHBOARD_URL_BASE_PATHNAME,
                                className="text-muted text-decoration-none",
                            ),
                        ],
                    ),
                ],
            ),
            # Unified dashboard control panel
            create_dashboard_control_panel(collection_name),
            # Empty state
            create_empty_state(collection_name),
            # Dashboard content (charts area only)
            create_dashboard_content(collection_name),
        ],
    )


def create_page_stores(collection_name: CollectionName) -> list:
    """
    Create the common dcc.Store components used by collection pages.

    :param collection_name: The collection name (e.g., "cc", "fips")
    :return: List of dcc.Store components
    """
    store_id = ComponentIDBuilder(collection_name)
    return [
        dcc.Store(id=store_id(ComponentID.COLLECTION_NAME), data=collection_name.value),
        dcc.Store(id=store_id(ComponentID.CURRENT_DASHBOARD_ID), data=None),
        dcc.Store(id=store_id(ComponentID.FILTER_STORE), data={}),
        dcc.Store(id=store_id(ComponentID.RENDER_TRIGGER), data=0),
        dcc.Store(id=store_id(ComponentID.DASHBOARD_LOADED), data=False),
        # Store for available fields metadata (populated from FilterFactory)
        # Format: [{"label": "Category", "value": "category", "data_type": "str"}, ...]
        dcc.Store(id=store_id(ComponentID.AVAILABLE_FIELDS), data=[]),
        # Store for filter specifications metadata (for chart modal filter options)
        # Format: [{"id": "cc-category-filter", "label": "Category", "field": "category", ...}, ...]
        dcc.Store(id=store_id(ComponentID.FILTER_SPECS), data=[]),
        # Store to track if modal metadata has been loaded (avoids reloading on every modal open)
        dcc.Store(id=store_id(ComponentID.METADATA_LOADED), data=False),
        # Store to signal when modal filter UI components are ready (triggers options population)
        dcc.Store(id=store_id(ComponentID.MODAL_FILTERS_READY), data=0),
        # Store for tracking which chart is being edited (None = create mode, chart_id = edit mode)
        dcc.Store(id=store_id(ComponentID.EDIT_CHART_ID), data=None),
        # Store for chart configurations (chart_id -> serialized Chart config)
        # Used to populate edit modal without database queries
        dcc.Store(id=store_id(ComponentID.CHART_CONFIGS_STORE), data={}),
    ]


def create_dashboard_control_panel(collection_name: CollectionName) -> dbc.Card:
    """
    Create the unified dashboard control panel with all controls in one card.

    Contains:
    - Dashboard selector and create new button
    - Dashboard name input
    - Action buttons (refresh, save)
    - Chart controls

    :param collection_name: The collection_name for component IDs
    :return: Card containing all dashboard controls
    """
    cid = ComponentIDBuilder(collection_name)
    return dbc.Card(
        className="mb-4 border-0",
        children=[
            dbc.CardBody(
                children=[
                    # Row 1: Dashboard selection / creation
                    dbc.Row(
                        className="g-3 align-items-end mb-4",
                        children=[
                            # Dashboard selector
                            dbc.Col(
                                width=12,
                                lg=True,
                                children=[
                                    dbc.Label(
                                        "Load Dashboard",
                                        className="fw-bold mb-2",
                                    ),
                                    dcc.Dropdown(
                                        id=cid(ComponentID.SELECTOR),
                                        options=[],
                                        placeholder="Select a saved dashboard...",
                                        clearable=True,
                                        className="dash-bootstrap",
                                    ),
                                ],
                            ),
                            # Create new button (on the right)
                            dbc.Col(
                                width=12,
                                lg="auto",
                                className="d-flex align-items-center",
                                children=[
                                    dbc.Button(
                                        [html.I(className="fas fa-plus me-2"), "Create New Dashboard"],
                                        id=cid(ComponentID.CREATE_BTN),
                                        n_clicks=0,
                                        color="success",
                                        size="lg",
                                        className="w-100 w-lg-auto",
                                    ),
                                ],
                            ),
                        ],
                    ),
                    # Row 2: Dashboard name and actions (shown when dashboard is active)
                    html.Div(
                        id=cid(ComponentID.DASHBOARD_HEADER),
                        style={"display": "none"},
                        children=[
                            html.Hr(className="my-3"),
                            dbc.Row(
                                className="g-3 align-items-end mb-4",
                                children=[
                                    # Dashboard name input
                                    dbc.Col(
                                        width=12,
                                        lg=True,
                                        children=[
                                            dbc.Label(
                                                "Dashboard Name",
                                                className="fw-bold mb-2",
                                            ),
                                            dbc.Input(
                                                id=cid(ComponentID.DASHBOARD_NAME_INPUT),
                                                type="text",
                                                value="New Dashboard",
                                                placeholder="Enter dashboard name...",
                                                size="lg",
                                            ),
                                        ],
                                    ),
                                    # Action buttons
                                    dbc.Col(
                                        width=12,
                                        lg="auto",
                                        className="d-flex align-items-center gap-2 flex-wrap",
                                        children=[
                                            dbc.Button(
                                                [html.I(className="fas fa-sync-alt me-2"), "Refresh All"],
                                                id=cid(ComponentID.UPDATE_ALL_BTN),
                                                n_clicks=0,
                                                disabled=True,
                                                color="secondary",
                                                outline=True,
                                                size="lg",
                                            ),
                                            dbc.Button(
                                                [html.I(className="fas fa-save me-2"), "Save Dashboard"],
                                                id=cid(ComponentID.SAVE_DASHBOARD_BTN),
                                                n_clicks=0,
                                                disabled=True,
                                                color="primary",
                                                size="lg",
                                            ),
                                        ],
                                    ),
                                ],
                            ),
                            # Row 3: Chart controls
                            html.Hr(className="my-3"),
                            dbc.Row(
                                className="g-3 align-items-end",
                                children=[
                                    # Predefined charts
                                    dbc.Col(
                                        width=12,
                                        lg=True,
                                        children=[
                                            dbc.Label(
                                                "Add Predefined Chart",
                                                className="fw-bold mb-2",
                                            ),
                                            dcc.Dropdown(
                                                id=cid(ComponentID.CHART_SELECTOR),
                                                options=[],
                                                placeholder="Select a predefined chart...",
                                                className="dash-bootstrap",
                                            ),
                                        ],
                                    ),
                                    # Add predefined button
                                    dbc.Col(
                                        width=12,
                                        lg="auto",
                                        className="d-flex align-items-center",
                                        children=[
                                            dbc.Button(
                                                [html.I(className="fas fa-plus me-2"), "Add Chart"],
                                                id=cid(ComponentID.ADD_CHART_BTN),
                                                n_clicks=0,
                                                color="primary",
                                                size="lg",
                                                className="w-100 w-lg-auto",
                                            ),
                                        ],
                                    ),
                                    # Divider
                                    dbc.Col(
                                        width="auto",
                                        className="d-none d-lg-flex align-items-center justify-content-center pb-1 text-muted",
                                        children=["or"],
                                    ),
                                    # Custom chart button
                                    dbc.Col(
                                        width=12,
                                        lg="auto",
                                        className="d-flex align-items-center",
                                        children=[
                                            dbc.Button(
                                                [
                                                    html.I(className="fas fa-magic me-2"),
                                                    "Create Custom Chart",
                                                ],
                                                id=cid(ComponentID.OPEN_CREATE_CHART_MODAL_BTN),
                                                n_clicks=0,
                                                color="success",
                                                size="lg",
                                                className="w-100 w-lg-auto",
                                            ),
                                        ],
                                    ),
                                ],
                            ),
                        ],
                    ),
                ],
            ),
        ],
    )


def create_empty_state(collection_name: CollectionName) -> html.Div:
    """
    Create the empty state display when no dashboard is selected.

    :param collection_name: The collection_name for component IDs
    :return: Div with empty state content
    """
    cid = ComponentIDBuilder(collection_name)
    return html.Div(
        id=cid(ComponentID.EMPTY_STATE),
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


def _create_chart_type_card(
    chart_type: ChartType, collection_name: CollectionName, is_selected: bool = False
) -> html.Div:
    """Create a visual card for chart type selection."""
    pattern_builder = PatternMatchingComponentID(collection_name)
    base_class = "chart-type-option text-center p-3 rounded"
    class_name = f"{base_class} selected" if is_selected else base_class
    icons = {
        ChartType.BAR: "fas fa-chart-bar",
        ChartType.STACKED_BAR: "fas fa-layer-group",
        ChartType.LINE: "fas fa-chart-line",
        ChartType.PIE: "fas fa-chart-pie",
        ChartType.SCATTER: "fas fa-braille",
        ChartType.BOX: "fas fa-box",
        ChartType.HISTOGRAM: "fas fa-signal",
    }
    labels = {
        ChartType.BAR: "Bar",
        ChartType.STACKED_BAR: "Stacked",
        ChartType.LINE: "Line",
        ChartType.PIE: "Pie",
        ChartType.SCATTER: "Scatter",
        ChartType.BOX: "Box",
        ChartType.HISTOGRAM: "Histogram",
    }
    return html.Div(
        className=class_name,
        id=pattern_builder.pattern(ComponentID.CHART_TYPE_CARD, chart_type.value),
        n_clicks=0,
        children=[
            html.I(className=f"{icons.get(chart_type, 'fas fa-chart-bar')} fa-2x mb-2"),
            html.Div(labels.get(chart_type, chart_type.value), className="small"),
        ],
    )


def create_chart_creation_modal(collection_name: CollectionName) -> dbc.Modal:
    """
    Create the modal for custom chart creation with modern visual design.

    Features:
    - Visual chart type selector with icons
    - Collapsible filter sections grouped by type
    - Y-axis settings collapsed by default
    - Clean, modern UI matching the design system

    :param collection_name: The collection_name for component IDs
    :return: Modal component for chart creation
    """
    cid = ComponentIDBuilder(collection_name)
    aggregation_options = [{"label": agg.value.upper(), "value": agg.value} for agg in AggregationType]

    return dbc.Modal(
        id=cid(ComponentID.CREATE_CHART_MODAL),
        is_open=False,
        size="xl",
        fullscreen=False,
        centered=True,
        scrollable=True,
        className="modal-xl-fluid",
        children=[
            dbc.ModalHeader(
                className="border-0 pb-0",
                children=[
                    html.Div(
                        className="w-100",
                        children=[
                            html.Small(
                                id=cid(ComponentID.MODAL_TITLE),
                                children=[html.I(className="fas fa-chart-bar me-2"), "Create Custom Chart"],
                                className="text-muted d-block mb-3",
                            ),
                            html.Div(
                                className="d-flex align-items-center mb-3",
                                children=[
                                    dbc.Input(
                                        id=cid(ComponentID.MODAL_CHART_TITLE),
                                        type="text",
                                        placeholder="New chart",
                                        value="",
                                        className="border-0 fs-4 fw-bold p-0 bg-transparent",
                                        style={"outline": "none", "boxShadow": "none"},
                                    ),
                                    html.I(
                                        className="fas fa-pencil-alt ms-2 text-muted",
                                        style={"fontSize": "0.9rem"},
                                    ),
                                ],
                            ),
                            # Validation feedback - shown under chart name
                            dbc.Alert(
                                id=cid(ComponentID.MODAL_VALIDATION_ALERT),
                                is_open=False,
                                color="danger",
                                className="mb-0",
                            ),
                        ],
                    ),
                ],
                close_button=True,
            ),
            dbc.ModalBody(
                className="pt-4",
                children=[
                    # Row 1: Chart Type Selection
                    dbc.Card(
                        className="mb-4 border-0 shadow-sm",
                        children=[
                            dbc.CardBody(
                                children=[
                                    # Chart type dropdown (hidden, used for value storage)
                                    dcc.Dropdown(
                                        id=cid(ComponentID.MODAL_CHART_TYPE),
                                        options=[
                                            {"label": ct.value.replace("_", " ").title(), "value": ct.value}
                                            for ct in ChartType
                                        ],
                                        value=ChartType.BAR.value,
                                        clearable=False,
                                        className="d-none",
                                    ),
                                    html.Div(
                                        className="d-flex align-items-center mb-3",
                                        children=[
                                            html.I(className="fas fa-chart-bar me-2 text-primary"),
                                            html.H5("Chart Type", className="mb-0 fw-bold"),
                                        ],
                                    ),
                                    dbc.Row(
                                        className="g-3",
                                        children=[
                                            dbc.Col(
                                                width=6,
                                                sm=4,
                                                md=3,
                                                lg=2,
                                                xl="auto",
                                                children=[
                                                    _create_chart_type_card(ct, collection_name, ct == ChartType.BAR),
                                                ],
                                            )
                                            for ct in ChartType
                                        ],
                                    ),
                                    html.Div(
                                        id=cid(ComponentID.CHART_TYPE_HELP),
                                        className="mt-3 text-muted small",
                                    ),
                                ],
                            ),
                        ],
                    ),
                    # Row 2: Data Selection (X-axis and Y-axis side by side)
                    dbc.Card(
                        className="mb-4 border-0 shadow-sm",
                        children=[
                            dbc.CardBody(
                                children=[
                                    html.Div(
                                        className="d-flex align-items-center mb-3",
                                        children=[
                                            html.I(className="fas fa-sliders-h me-2 text-primary"),
                                            html.H5("Data Selection", className="mb-0 fw-bold"),
                                        ],
                                    ),
                                    dbc.Row(
                                        className="g-4",
                                        children=[
                                            # X-axis settings
                                            dbc.Col(
                                                width=12,
                                                lg=6,
                                                children=[
                                                    html.Div(
                                                        className="mb-3",
                                                        children=[
                                                            html.Div(
                                                                className="d-flex align-items-center mb-2",
                                                                children=[
                                                                    html.I(
                                                                        className="fas fa-arrows-alt-h me-2 text-muted"
                                                                    ),
                                                                    html.Span("X-Axis", className="fw-bold"),
                                                                ],
                                                            ),
                                                            # Primary field (X-axis)
                                                            dbc.Label(
                                                                "Group By",
                                                                className="small text-muted mb-1",
                                                            ),
                                                            dcc.Dropdown(
                                                                id=cid(ComponentID.MODAL_X_FIELD),
                                                                options=[],
                                                                placeholder="Select field...",
                                                                className="dash-bootstrap mb-3",
                                                            ),
                                                            # X-axis label
                                                            dbc.Label(
                                                                "Label",
                                                                className="small text-muted mb-1",
                                                            ),
                                                            dbc.Input(
                                                                id=cid(ComponentID.MODAL_X_LABEL),
                                                                type="text",
                                                                placeholder="Optional label...",
                                                                value="",
                                                                size="sm",
                                                                className="mb-3",
                                                            ),
                                                            # Color By (secondary grouping)
                                                            dbc.Label(
                                                                "Color By",
                                                                className="small text-muted mb-1",
                                                            ),
                                                            dcc.Dropdown(
                                                                id=cid(ComponentID.MODAL_COLOR_FIELD),
                                                                options=[],
                                                                placeholder="Optional secondary grouping...",
                                                                className="dash-bootstrap",
                                                                clearable=True,
                                                            ),
                                                            # Hidden collapse toggle (for backwards compatibility)
                                                            html.Div(
                                                                className="d-none",
                                                                children=[
                                                                    dbc.Button(
                                                                        id=cid(ComponentID.COLOR_BY_TOGGLE),
                                                                        n_clicks=0,
                                                                    ),
                                                                    dbc.Collapse(
                                                                        id=cid(ComponentID.COLOR_BY_COLLAPSE),
                                                                        is_open=True,
                                                                    ),
                                                                    html.I(id=cid(ComponentID.COLOR_BY_ICON)),
                                                                    # Dummy components for selection toggle
                                                                    html.Div(
                                                                        id=cid(ComponentID.SELECTION_TOGGLE), n_clicks=0
                                                                    ),
                                                                    html.I(id=cid(ComponentID.SELECTION_ICON)),
                                                                    dbc.Collapse(
                                                                        id=cid(ComponentID.SELECTION_COLLAPSE),
                                                                        is_open=True,
                                                                    ),
                                                                ],
                                                            ),
                                                        ],
                                                    ),
                                                ],
                                            ),
                                            # Y-axis settings
                                            dbc.Col(
                                                width=12,
                                                lg=6,
                                                children=[
                                                    html.Div(
                                                        className="mb-3",
                                                        children=[
                                                            html.Div(
                                                                className="d-flex align-items-center mb-2",
                                                                children=[
                                                                    html.I(
                                                                        className="fas fa-arrows-alt-v me-2 text-muted"
                                                                    ),
                                                                    html.Span("Y-Axis", className="fw-bold"),
                                                                ],
                                                            ),
                                                            # Aggregation type
                                                            dbc.Label(
                                                                "Aggregation",
                                                                className="small text-muted mb-1",
                                                            ),
                                                            dcc.Dropdown(
                                                                id=cid(ComponentID.MODAL_AGGREGATION),
                                                                options=aggregation_options,  # type: ignore[arg-type]
                                                                value=AggregationType.COUNT.value,
                                                                clearable=False,
                                                                className="dash-bootstrap mb-3",
                                                            ),
                                                            # Field to aggregate
                                                            dbc.Label(
                                                                "Field to Aggregate",
                                                                className="small text-muted mb-1",
                                                            ),
                                                            dcc.Dropdown(
                                                                id=cid(ComponentID.MODAL_Y_FIELD),
                                                                options=[],
                                                                placeholder="For SUM/AVG/MIN/MAX...",
                                                                disabled=True,
                                                                className="dash-bootstrap mb-1",
                                                            ),
                                                            dbc.FormText(
                                                                id=cid(ComponentID.MODAL_Y_FIELD_HELP),
                                                                children="Not required for COUNT.",
                                                                className="text-muted small mb-3",
                                                            ),
                                                            # Y-axis label
                                                            dbc.Label(
                                                                "Label",
                                                                className="small text-muted mb-1",
                                                            ),
                                                            dbc.Input(
                                                                id=cid(ComponentID.MODAL_Y_LABEL),
                                                                type="text",
                                                                placeholder="Optional label...",
                                                                value="",
                                                                size="sm",
                                                                className="mb-3",
                                                            ),
                                                            # Display options
                                                            html.Hr(className="my-3"),
                                                            dbc.Checkbox(
                                                                id=cid(ComponentID.MODAL_SHOW_LEGEND),
                                                                label="Show Legend",
                                                                value=True,
                                                                className="mb-2",
                                                            ),
                                                            dbc.Checkbox(
                                                                id=cid(ComponentID.MODAL_SHOW_GRID),
                                                                label="Show Grid",
                                                                value=True,
                                                            ),
                                                            # Hidden collapse toggle (for backwards compatibility)
                                                            html.Div(
                                                                className="d-none",
                                                                children=[
                                                                    html.Div(
                                                                        id=cid(ComponentID.VALUE_TEXT_TOGGLE),
                                                                        n_clicks=0,
                                                                    ),
                                                                    html.I(id=cid(ComponentID.VALUE_TEXT_ICON)),
                                                                    dbc.Collapse(
                                                                        id=cid(ComponentID.VALUE_TEXT_COLLAPSE),
                                                                        is_open=True,
                                                                    ),
                                                                ],
                                                            ),
                                                        ],
                                                    ),
                                                ],
                                            ),
                                        ],
                                    ),
                                ],
                            ),
                        ],
                    ),
                    # Row 3: Filters
                    dbc.Card(
                        className="mb-4 border-0 shadow-sm",
                        children=[
                            dbc.CardBody(
                                children=[
                                    html.Div(
                                        className="d-flex align-items-center mb-3",
                                        children=[
                                            html.I(className="fas fa-filter me-2 text-primary"),
                                            html.H5("Filters", className="mb-0 fw-bold"),
                                        ],
                                    ),
                                    # Filter sections container - populated dynamically
                                    html.Div(
                                        id=cid(ComponentID.MODAL_FILTERS_CONTAINER),
                                        className="modal-filters-container",
                                        children=[],
                                    ),
                                ],
                            ),
                        ],
                    ),
                ],
            ),
            dbc.ModalFooter(
                className="border-0 pt-0",
                children=[
                    dbc.Button(
                        "Cancel",
                        id=cid(ComponentID.MODAL_CANCEL_BTN),
                        color="secondary",
                        outline=True,
                        size="lg",
                    ),
                    dbc.Button(
                        id=cid(ComponentID.MODAL_CREATE_BTN),
                        color="primary",
                        size="lg",
                        children=[html.I(className="fas fa-save me-2"), "Save Chart"],
                    ),
                ],
            ),
        ],
    )


def create_dashboard_content(collection_name: CollectionName) -> html.Div:
    """
    Create the dashboard content area (chart container and modal only).

    The controls are now in the unified control panel (create_dashboard_control_panel).

    :param collection_name: The collection_name for component IDs
    :return: Div containing chart container and modal
    """
    cid = ComponentIDBuilder(collection_name)
    return html.Div(
        id=cid(ComponentID.DASHBOARD_CONTENT),
        style={"display": "none"},
        children=[
            # Chart container
            html.Div(id=cid(ComponentID.CHART_CONTAINER)),
            # Chart creation modal
            create_chart_creation_modal(collection_name),
        ],
    )
