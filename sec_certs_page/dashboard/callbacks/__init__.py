from typing import TYPE_CHECKING

from ..filters.factory import FilterFactory
from ..types.common import CollectionType
from .charts import register_chart_callbacks, register_pattern_matching_callbacks
from .dashboard import register_dashboard_callbacks
from .filters import register_filter_callbacks
from .modal import register_modal_callbacks

if TYPE_CHECKING:
    from ..base import Dash
    from ..chart.registry import ChartRegistry
    from ..data import DataService
    from ..manager import DashboardManager


def register_all_callbacks(
    dash_app: "Dash",
    data_service: "DataService",
    filter_factories: dict[CollectionType, FilterFactory],
    chart_registries: dict[CollectionType, "ChartRegistry"],
    dashboard_manager: "DashboardManager",
) -> None:
    """The Dash callbacks need to be registered after the Dash instance creation
    and should be registered after pages are registered.

    Before registering the callbacks, filter factories and chart registries
    for each dataset type need to be initialized.
    """
    for collection_type in CollectionType:
        filter_factory = filter_factories[collection_type]
        chart_registry = chart_registries[collection_type]

        register_dashboard_callbacks(
            dash_app=dash_app,
            collection_type=collection_type,
            dashboard_manager=dashboard_manager,
            chart_registry=chart_registry,
        )

        register_chart_callbacks(
            dash_app=dash_app,
            collection_type=collection_type,
            chart_registry=chart_registry,
            data_service=data_service,
        )

        register_filter_callbacks(
            dash_app=dash_app,
            collection_type=collection_type,
            filter_factory=filter_factory,
            data_service=data_service,
        )

        register_modal_callbacks(
            dash_app=dash_app,
            collection_type=collection_type,
            data_service=data_service,
            chart_registry=chart_registry,
        )

    register_pattern_matching_callbacks(dash_app, chart_registries)


__all__ = [
    "register_all_callbacks",
    "register_dashboard_callbacks",
    "register_chart_callbacks",
    "register_filter_callbacks",
    "register_modal_callbacks",
]
