import dash_bootstrap_components as dbc
from dash import html
from dash.development.base_component import Component
from flask_login import current_user


def get_current_user_id() -> str | None:
    try:
        if current_user and current_user.is_authenticated:
            return current_user.id
    except RuntimeError:
        pass
    return None


def create_chart_wrapper(
    chart_id: str,
    title: str,
    chart_component: Component,
    is_editable: bool = False,
) -> dbc.Card:
    """
    Wrap a chart component in a card with control buttons.

    :param is_editable: Shows edit button for custom charts (not predefined ones).
    """
    buttons = []

    if is_editable:
        buttons.append(
            dbc.Button(
                html.I(className="fas fa-edit"),
                id={"type": "chart-edit", "index": chart_id},
                color="primary",
                outline=True,
                title="Edit this chart",
            )
        )

    buttons.extend(
        [
            dbc.Button(
                html.I(className="fas fa-sync-alt"),
                id={"type": "chart-refresh", "index": chart_id},
                color="success",
                outline=True,
                title="Refresh this chart",
            ),
            dbc.Button(
                html.I(className="fas fa-times"),
                id={"type": "remove-chart", "index": chart_id},
                color="danger",
                outline=True,
                title="Remove this chart",
            ),
        ]
    )

    return dbc.Card(
        id={"type": "chart-wrapper", "index": chart_id},
        className="mb-4 shadow-sm",
        children=[
            dbc.CardHeader(
                className="d-flex justify-content-between align-items-center",
                children=[
                    html.H5(title, className="mb-0"),
                    dbc.ButtonGroup(size="sm", children=buttons),
                ],
            ),
            dbc.CardBody(
                id={"type": "chart-content", "index": chart_id},
                children=chart_component,
            ),
        ],
    )
