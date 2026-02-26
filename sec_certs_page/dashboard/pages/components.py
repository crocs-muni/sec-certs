"""Reusable UI components for dashboard pages.

This module contains small, reusable layout building blocks that help maintain
consistency across pages and reduce code duplication.
"""

import dash_bootstrap_components as dbc
from dash import dcc, html

from ..dependencies import ComponentID, ComponentIDBuilder, PatternMatchingComponentID
from ..types.chart import ChartType
from ..types.filter import AggregationType


def section_header(title: str, icon: str, icon_color: str = "text-primary") -> html.Div:
    """Create a section header with icon and title.

    :param title: The section title text
    :param icon: Font Awesome icon class (e.g., "fas fa-chart-bar")
    :param icon_color: Bootstrap text color class (default: "text-primary")
    :return: Div containing the header
    """
    return html.Div(
        className="d-flex align-items-center mb-3",
        children=[
            html.I(className=f"{icon} me-2 {icon_color}"),
            html.H5(title, className="mb-0 fw-bold"),
        ],
    )


def subsection_header(title: str, icon: str, icon_color: str = "text-muted") -> html.Div:
    """Create a subsection header with icon and title.

    :param title: The subsection title text
    :param icon: Font Awesome icon class
    :param icon_color: Bootstrap text color class (default: "text-muted")
    :return: Div containing the header
    """
    return html.Div(
        className="d-flex align-items-center mb-2",
        children=[
            html.I(className=f"{icon} me-2 {icon_color}"),
            html.Span(title, className="fw-bold"),
        ],
    )


def labeled_dropdown(
    component_id: str,
    label: str,
    placeholder: str = "Select...",
    options: list | None = None,
    value: str | None = None,
    clearable: bool = True,
    disabled: bool = False,
    class_name: str = "mb-3",
    label_class: str = "small text-muted mb-1",
) -> html.Div:
    """Create a labeled dropdown component.

    :param component_id: The component ID for the dropdown
    :param label: Label text above the dropdown
    :param placeholder: Placeholder text when no value selected
    :param options: List of options (default: empty list)
    :param value: Initial selected value
    :param clearable: Whether the dropdown can be cleared
    :param disabled: Whether the dropdown is disabled
    :param class_name: Additional CSS classes for the container
    :param label_class: CSS classes for the label
    :return: Div containing label and dropdown
    """
    return html.Div(
        className=class_name,
        children=[
            dbc.Label(label, className=label_class),
            dcc.Dropdown(
                id=component_id,
                options=options or [],
                value=value,
                placeholder=placeholder,
                clearable=clearable,
                disabled=disabled,
                className="dash-bootstrap",
            ),
        ],
    )


def labeled_input(
    component_id: str,
    label: str,
    placeholder: str = "",
    value: str = "",
    input_type: str = "text",
    size: str = "sm",
    class_name: str = "mb-3",
    label_class: str = "small text-muted mb-1",
) -> html.Div:
    """Create a labeled input component.

    :param component_id: The component ID for the input
    :param label: Label text above the input
    :param placeholder: Placeholder text
    :param value: Initial value
    :param input_type: Input type (text, number, etc.)
    :param size: Bootstrap size (sm, md, lg)
    :param class_name: Additional CSS classes for the container
    :param label_class: CSS classes for the label
    :return: Div containing label and input
    """
    return html.Div(
        className=class_name,
        children=[
            dbc.Label(label, className=label_class),
            dbc.Input(
                id=component_id,
                type=input_type,
                placeholder=placeholder,
                value=value,
                size=size,
            ),
        ],
    )


def section_card(children: list, class_name: str = "mb-4 border-0 shadow-sm") -> dbc.Card:
    """Create a card wrapper for a section.

    :param children: Card body content
    :param class_name: CSS classes for the card
    :return: Card component
    """
    return dbc.Card(
        className=class_name,
        children=[dbc.CardBody(children=children)],
    )


CHART_TYPE_ICONS = {
    ChartType.BAR: "fas fa-chart-bar",
    ChartType.STACKED_BAR: "fas fa-layer-group",
    ChartType.LINE: "fas fa-chart-line",
    ChartType.PIE: "fas fa-chart-pie",
    ChartType.SCATTER: "fas fa-braille",
    ChartType.BOX: "fas fa-box",
    ChartType.HISTOGRAM: "fas fa-signal",
}

CHART_TYPE_LABELS = {
    ChartType.BAR: "Bar",
    ChartType.STACKED_BAR: "Stacked",
    ChartType.LINE: "Line",
    ChartType.PIE: "Pie",
    ChartType.SCATTER: "Scatter",
    ChartType.BOX: "Box",
    ChartType.HISTOGRAM: "Histogram",
}


def chart_type_card(
    chart_type: ChartType,
    pattern_builder: PatternMatchingComponentID,
    is_selected: bool = False,
) -> html.Div:
    """Create a visual card for chart type selection.

    :param chart_type: The chart type enum value
    :param pattern_builder: Pattern matching component ID builder
    :param is_selected: Whether this card is currently selected
    :return: Div containing the chart type card
    """
    base_class = "chart-type-option text-center p-3 rounded"
    class_name = f"{base_class} selected" if is_selected else base_class

    icon = CHART_TYPE_ICONS.get(chart_type, "fas fa-chart-bar")
    label = CHART_TYPE_LABELS.get(chart_type, chart_type.value)

    return html.Div(
        className=class_name,
        id=pattern_builder.pattern(ComponentID.CHART_TYPE_CARD, chart_type.value),
        n_clicks=0,
        children=[
            html.I(className=f"{icon} fa-2x mb-2"),
            html.Div(label, className="small"),
        ],
    )


def chart_type_grid(
    pattern_builder: PatternMatchingComponentID,
    selected_type: ChartType = ChartType.BAR,
) -> dbc.Row:
    """Create a grid of chart type selection cards.

    :param pattern_builder: Pattern matching component ID builder
    :param selected_type: Currently selected chart type
    :return: Row containing all chart type cards
    """
    return dbc.Row(
        className="g-3",
        children=[
            dbc.Col(
                width=6,
                sm=4,
                md=3,
                lg=2,
                xl="auto",
                children=[chart_type_card(ct, pattern_builder, ct == selected_type)],
            )
            for ct in ChartType
        ],
    )


def step_item(number: int | str, text: str) -> html.Div:
    """Create a numbered step item.

    :param number: Step number
    :param text: Step description
    :return: Div containing the step
    """
    return html.Div(
        className="d-flex align-items-start",
        children=[
            html.Span(
                str(number),
                className="badge bg-primary rounded-circle me-3 fs-6",
            ),
            html.Span(text, className="text-muted"),
        ],
    )


def steps_row(steps: list[str]) -> dbc.Row:
    """Create a row of numbered steps.

    :param steps: List of step descriptions
    :return: Row containing all steps
    """
    return dbc.Row(
        className="g-4",
        children=[
            dbc.Col(
                width=12,
                md=6,
                lg=True,
                children=[step_item(i + 1, text)],
            )
            for i, text in enumerate(steps)
        ],
    )


def hidden_collapse_components(cid: ComponentIDBuilder) -> html.Div:
    """Create hidden components needed for collapse callbacks.

    These are kept for backwards compatibility with existing callbacks.

    :param cid: Component ID builder
    :return: Hidden div with dummy components
    """
    return html.Div(
        className="d-none",
        children=[
            dbc.Button(id=cid(ComponentID.COLOR_BY_TOGGLE), n_clicks=0),
            dbc.Collapse(id=cid(ComponentID.COLOR_BY_COLLAPSE), is_open=True),
            html.I(id=cid(ComponentID.COLOR_BY_ICON)),
            html.Div(id=cid(ComponentID.SELECTION_TOGGLE), n_clicks=0),
            html.I(id=cid(ComponentID.SELECTION_ICON)),
            dbc.Collapse(id=cid(ComponentID.SELECTION_COLLAPSE), is_open=True),
            html.Div(id=cid(ComponentID.VALUE_TEXT_TOGGLE), n_clicks=0),
            html.I(id=cid(ComponentID.VALUE_TEXT_ICON)),
            dbc.Collapse(id=cid(ComponentID.VALUE_TEXT_COLLAPSE), is_open=True),
        ],
    )


def get_aggregation_options() -> list[dict]:
    """Get dropdown options for aggregation types.

    :return: List of option dicts with label and value
    """
    return [{"label": agg.value.upper(), "value": agg.value} for agg in AggregationType]
