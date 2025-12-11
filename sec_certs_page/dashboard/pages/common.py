"""Common utilities for dashboard collection pages.

This module provides the layout factory functions for collection dashboard pages.
It uses reusable components from the components module to build consistent UIs.
"""

import dash_bootstrap_components as dbc
from dash import dcc, html

from ... import DASHBOARD_URL_BASE_PATHNAME
from ..dependencies import ComponentID, ComponentIDBuilder, PatternMatchingComponentID
from ..types.chart import ChartType
from ..types.common import CollectionName
from .components import (
    chart_type_grid,
    get_aggregation_options,
    hidden_collapse_components,
    labeled_dropdown,
    labeled_input,
    section_card,
    section_header,
    subsection_header,
)


def create_collection_page_layout(collection_name: CollectionName, title: str) -> html.Div:
    """Create the complete layout for a collection dashboard page.

    :param collection_name: The collection enum value
    :param title: The page title to display
    :return: Complete page layout
    """
    cid = ComponentIDBuilder(collection_name)
    return html.Div(
        className="py-3",
        children=[
            # State stores
            *_create_page_stores(collection_name),
            # Toast for notifications
            _create_toast(cid),
            # Page header
            _create_page_header(title),
            # Unified dashboard control panel
            _create_dashboard_control_panel(collection_name),
            # Empty state
            _create_empty_state(collection_name),
            # Dashboard content (charts area only)
            _create_dashboard_content(collection_name),
        ],
    )


def _create_page_stores(collection_name: CollectionName) -> list:
    """Create the common dcc.Store components used by collection pages.

    :param collection_name: The collection name (e.g., "cc", "fips")
    :return: List of dcc.Store components
    """
    cid = ComponentIDBuilder(collection_name)
    return [
        dcc.Store(id=cid(ComponentID.COLLECTION_NAME), data=collection_name.value),
        dcc.Store(id=cid(ComponentID.CURRENT_DASHBOARD_ID), data=None),
        dcc.Store(id=cid(ComponentID.FILTER_STORE), data={}),
        dcc.Store(id=cid(ComponentID.RENDER_TRIGGER), data=0),
        dcc.Store(id=cid(ComponentID.DASHBOARD_LOADED), data=False),
        dcc.Store(id=cid(ComponentID.AVAILABLE_FIELDS), data=[]),
        dcc.Store(id=cid(ComponentID.FILTER_SPECS), data=[]),
        dcc.Store(id=cid(ComponentID.METADATA_LOADED), data=False),
        dcc.Store(id=cid(ComponentID.MODAL_FILTERS_READY), data=0),
        dcc.Store(id=cid(ComponentID.EDIT_CHART_ID), data=None),
        dcc.Store(id=cid(ComponentID.CHART_CONFIGS_STORE), data={}),
    ]


def _create_toast(cid: ComponentIDBuilder) -> dbc.Toast:
    """Create the notification toast component.

    :param cid: Component ID builder
    :return: Toast component
    """
    return dbc.Toast(
        id=cid(ComponentID.DASHBOARD_TOAST),
        header="Dashboard",
        is_open=False,
        dismissable=True,
        duration=4000,
        icon="info",
        style={"position": "fixed", "top": 66, "right": 10, "width": 350, "zIndex": 1050},
    )


def _create_page_header(title: str) -> dbc.Row:
    """Create the page header with title and back link.

    :param title: The page title
    :return: Row containing the header
    """
    return dbc.Row(
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
    )


def _create_dashboard_control_panel(collection_name: CollectionName) -> dbc.Card:
    """Create the unified dashboard control panel with all controls in one card.

    Contains:
    - Dashboard selector and create new button
    - Dashboard name input
    - Action buttons (refresh, save)
    - Chart controls

    :param collection_name: The collection name for component IDs
    :return: Card containing all dashboard controls
    """
    cid = ComponentIDBuilder(collection_name)
    return dbc.Card(
        className="mb-4 border-0",
        children=[
            dbc.CardBody(
                children=[
                    # Row 1: Dashboard selection / creation
                    _create_dashboard_selector_row(cid),
                    # Row 2: Dashboard name and actions (shown when dashboard is active)
                    _create_dashboard_active_controls(cid),
                ],
            ),
        ],
    )


def _create_dashboard_selector_row(cid: ComponentIDBuilder) -> dbc.Row:
    """Create the dashboard selector and create button row.

    :param cid: Component ID builder
    :return: Row with selector and create button
    """
    return dbc.Row(
        className="g-3 align-items-end mb-4",
        children=[
            # Dashboard selector
            dbc.Col(
                width=12,
                lg=True,
                children=[
                    dbc.Label("Load Dashboard", className="fw-bold mb-2"),
                    dcc.Dropdown(
                        id=cid(ComponentID.SELECTOR),
                        options=[],
                        placeholder="Select a saved dashboard...",
                        clearable=True,
                        className="dash-bootstrap",
                    ),
                ],
            ),
            # Create new button
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
    )


def _create_dashboard_active_controls(cid: ComponentIDBuilder) -> html.Div:
    """Create the controls shown when a dashboard is active.

    :param cid: Component ID builder
    :return: Div containing active dashboard controls
    """
    return html.Div(
        id=cid(ComponentID.DASHBOARD_HEADER),
        style={"display": "none"},
        children=[
            html.Hr(className="my-3"),
            # Dashboard name and action buttons
            _create_dashboard_name_row(cid),
            html.Hr(className="my-3"),
            # Chart controls
            _create_chart_controls_row(cid),
        ],
    )


def _create_dashboard_name_row(cid: ComponentIDBuilder) -> dbc.Row:
    """Create the dashboard name and action buttons row.

    :param cid: Component ID builder
    :return: Row with name input and action buttons
    """
    return dbc.Row(
        className="g-3 align-items-end mb-4",
        children=[
            # Dashboard name input
            dbc.Col(
                width=12,
                lg=True,
                children=[
                    dbc.Label("Dashboard Name", className="fw-bold mb-2"),
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
                        className="refresh-all-btn",
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
    )


def _create_chart_controls_row(cid: ComponentIDBuilder) -> dbc.Row:
    """Create the chart selection and creation controls row.

    :param cid: Component ID builder
    :return: Row with chart controls
    """
    return dbc.Row(
        className="g-3 align-items-end",
        children=[
            # Predefined charts dropdown
            dbc.Col(
                width=12,
                lg=True,
                children=[
                    dbc.Label("Add Predefined Chart", className="fw-bold mb-2"),
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
                        [html.I(className="fas fa-magic me-2"), "Create Custom Chart"],
                        id=cid(ComponentID.OPEN_CREATE_CHART_MODAL_BTN),
                        n_clicks=0,
                        color="success",
                        size="lg",
                        className="w-100 w-lg-auto",
                    ),
                ],
            ),
        ],
    )


def _create_empty_state(collection_name: CollectionName) -> html.Div:
    """Create the empty state display when no dashboard is selected.

    :param collection_name: The collection name for component IDs
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


def _create_dashboard_content(collection_name: CollectionName) -> html.Div:
    """Create the dashboard content area (chart container and modal only).

    :param collection_name: The collection name for component IDs
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
            _create_chart_creation_modal(collection_name),
        ],
    )


# =============================================================================
# Chart Creation Modal
# =============================================================================


def _create_chart_creation_modal(collection_name: CollectionName) -> dbc.Modal:
    """Create the modal for custom chart creation with modern visual design.

    :param collection_name: The collection name for component IDs
    :return: Modal component for chart creation
    """
    cid = ComponentIDBuilder(collection_name)
    pattern_builder = PatternMatchingComponentID(collection_name)

    return dbc.Modal(
        id=cid(ComponentID.CREATE_CHART_MODAL),
        is_open=False,
        size="xl",
        fullscreen=False,
        centered=True,
        scrollable=True,
        className="modal-xl-fluid",
        children=[
            _create_modal_header(cid),
            _create_modal_body(cid, pattern_builder),
            _create_modal_footer(cid),
        ],
    )


def _create_modal_header(cid: ComponentIDBuilder) -> dbc.ModalHeader:
    """Create the modal header with editable chart title.

    :param cid: Component ID builder
    :return: Modal header component
    """
    return dbc.ModalHeader(
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
    )


def _create_modal_body(cid: ComponentIDBuilder, pattern_builder: PatternMatchingComponentID) -> dbc.ModalBody:
    """Create the modal body with chart configuration sections.

    :param cid: Component ID builder
    :param pattern_builder: Pattern matching component ID builder
    :return: Modal body component
    """
    return dbc.ModalBody(
        className="pt-4",
        children=[
            # Chart Type Selection
            _create_chart_type_section(cid, pattern_builder),
            # Data Selection (X-axis and Y-axis)
            _create_data_selection_section(cid),
            # Filters
            _create_filters_section(cid),
        ],
    )


def _create_chart_type_section(cid: ComponentIDBuilder, pattern_builder: PatternMatchingComponentID) -> dbc.Card:
    """Create the chart type selection section.

    :param cid: Component ID builder
    :param pattern_builder: Pattern matching component ID builder
    :return: Card containing chart type selection
    """
    return section_card(
        [
            # Hidden dropdown for value storage
            dcc.Dropdown(
                id=cid(ComponentID.MODAL_CHART_TYPE),
                options=[{"label": ct.value.replace("_", " ").title(), "value": ct.value} for ct in ChartType],
                value=ChartType.BAR.value,
                clearable=False,
                className="d-none",
            ),
            section_header("Chart Type", "fas fa-chart-bar"),
            chart_type_grid(pattern_builder, ChartType.BAR),
            html.Div(id=cid(ComponentID.CHART_TYPE_HELP), className="mt-3 text-muted small"),
        ]
    )


def _create_data_selection_section(cid: ComponentIDBuilder) -> dbc.Card:
    """Create the data selection section with X and Y axis settings.

    :param cid: Component ID builder
    :return: Card containing data selection controls
    """
    return section_card(
        [
            section_header("Data Selection", "fas fa-sliders-h"),
            dbc.Row(
                className="g-4",
                children=[
                    # X-axis settings
                    dbc.Col(width=12, lg=6, children=[_create_x_axis_settings(cid)]),
                    # Y-axis settings
                    dbc.Col(width=12, lg=6, children=[_create_y_axis_settings(cid)]),
                ],
            ),
        ]
    )


def _create_x_axis_settings(cid: ComponentIDBuilder) -> html.Div:
    """Create X-axis configuration controls.

    :param cid: Component ID builder
    :return: Div containing X-axis settings
    """
    return html.Div(
        className="mb-3",
        children=[
            subsection_header("X-Axis", "fas fa-arrows-alt-h"),
            labeled_dropdown(
                component_id=cid(ComponentID.MODAL_X_FIELD),
                label="Group By",
                placeholder="Select field...",
            ),
            labeled_input(
                component_id=cid(ComponentID.MODAL_X_LABEL),
                label="Label",
                placeholder="Optional label...",
            ),
            labeled_dropdown(
                component_id=cid(ComponentID.MODAL_COLOR_FIELD),
                label="Color By",
                placeholder="Optional secondary grouping...",
                class_name="",
            ),
            # Hidden components for backwards compatibility
            hidden_collapse_components(cid),
        ],
    )


def _create_y_axis_settings(cid: ComponentIDBuilder) -> html.Div:
    """Create Y-axis configuration controls.

    :param cid: Component ID builder
    :return: Div containing Y-axis settings
    """
    return html.Div(
        className="mb-3",
        children=[
            subsection_header("Y-Axis", "fas fa-arrows-alt-v"),
            # Aggregation dropdown
            html.Div(
                className="mb-3",
                children=[
                    dbc.Label("Aggregation", className="small text-muted mb-1"),
                    dcc.Dropdown(
                        id=cid(ComponentID.MODAL_AGGREGATION),
                        options=get_aggregation_options(),
                        value="count",
                        clearable=False,
                        className="dash-bootstrap",
                    ),
                ],
            ),
            # Field to aggregate
            html.Div(
                className="mb-1",
                children=[
                    dbc.Label("Field to Aggregate", className="small text-muted mb-1"),
                    dcc.Dropdown(
                        id=cid(ComponentID.MODAL_Y_FIELD),
                        options=[],
                        placeholder="For SUM/AVG/MIN/MAX...",
                        disabled=True,
                        className="dash-bootstrap",
                    ),
                ],
            ),
            dbc.FormText(
                id=cid(ComponentID.MODAL_Y_FIELD_HELP),
                children="Not required for COUNT.",
                className="text-muted small mb-3",
            ),
            labeled_input(
                component_id=cid(ComponentID.MODAL_Y_LABEL),
                label="Label",
                placeholder="Optional label...",
            ),
            # Y Values options
            dbc.Checkbox(
                id=cid(ComponentID.MODAL_SHOW_NON_ZERO),
                label="Show only non-zero values",
                value=False,
                className="mb-2",
            ),
            dbc.Checkbox(
                id=cid(ComponentID.MODAL_Y_LOG_SCALE),
                label="Y-axis Logarithmic Scale",
                value=False,
                className="mb-2",
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
                className="mb-2",
            ),
        ],
    )


def _create_filters_section(cid: ComponentIDBuilder) -> dbc.Card:
    """Create the filters section.

    :param cid: Component ID builder
    :return: Card containing filters
    """
    return section_card(
        [
            section_header("Filters", "fas fa-filter"),
            html.Div(
                id=cid(ComponentID.MODAL_FILTERS_CONTAINER),
                className="modal-filters-container",
                children=[],
            ),
        ]
    )


def _create_modal_footer(cid: ComponentIDBuilder) -> dbc.ModalFooter:
    """Create the modal footer with action buttons.

    :param cid: Component ID builder
    :return: Modal footer component
    """
    return dbc.ModalFooter(
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
    )
