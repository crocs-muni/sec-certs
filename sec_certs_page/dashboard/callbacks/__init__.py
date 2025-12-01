from typing import TYPE_CHECKING

from ..filters.factory import FilterFactory
from ..types.common import CollectionName
from .charts import register_chart_callbacks, register_pattern_matching_callbacks
from .dashboard import register_dashboard_callbacks
from .filters import register_filter_callbacks
from .modal import register_modal_callbacks

if TYPE_CHECKING:
    from ...common.dash.base import Dash
    from ..chart.registry import ChartRegistry
    from ..data import DataService
    from ..manager import DashboardManager


def register_all_callbacks(
    dash_app: "Dash",
    data_service: "DataService",
    filter_factories: dict[CollectionName, FilterFactory],
    chart_registries: dict[CollectionName, "ChartRegistry"],
    dashboard_manager: "DashboardManager",
) -> None:
    for dataset_type in CollectionName:
        filter_factory = filter_factories[dataset_type]
        chart_registry = chart_registries[dataset_type]
        prefix = dataset_type.value

        register_dashboard_callbacks(
            dash_app=dash_app,
            prefix=prefix,
            dataset_type=dataset_type,
            dashboard_manager=dashboard_manager,
            chart_registry=chart_registry,
        )

        register_chart_callbacks(
            dash_app=dash_app,
            prefix=prefix,
            chart_registry=chart_registry,
        )

        register_filter_callbacks(
            dash_app=dash_app,
            prefix=prefix,
            filter_factory=filter_factory,
            data_service=data_service,
        )

        register_modal_callbacks(
            dash_app=dash_app,
            prefix=prefix,
            dataset_type=dataset_type,
            data_service=data_service,
            chart_registry=chart_registry,
            filter_factory=filter_factory,
        )

    register_pattern_matching_callbacks(dash_app, chart_registries)


__all__ = [
    "register_all_callbacks",
    "register_dashboard_callbacks",
    "register_chart_callbacks",
    "register_filter_callbacks",
    "register_modal_callbacks",
]
