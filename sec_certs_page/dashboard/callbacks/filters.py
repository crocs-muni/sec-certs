from typing import TYPE_CHECKING

from dash.dependencies import Input, Output

from ..filters.factory import FilterFactory
from ..types.filter import FilterComponentType

if TYPE_CHECKING:
    from ...common.dash.base import Dash
    from ..data import DataService


def register_filter_callbacks(
    dash_app: "Dash",
    prefix: str,
    filter_factory: FilterFactory,
    data_service: "DataService",
) -> None:
    _register_filter_options(dash_app, filter_factory, data_service)
    _register_filter_store(dash_app, prefix, filter_factory)
    _register_button_states(dash_app, prefix)
    _register_available_fields(dash_app, prefix, filter_factory)
    _register_filter_specs(dash_app, prefix, filter_factory)


def _register_filter_options(
    dash_app: "Dash",
    filter_factory: FilterFactory,
    data_service: "DataService",
) -> None:
    for filter_id, filter_spec in filter_factory.registry.get_all_filters().items():
        if filter_spec.component_params.component_type not in (
            FilterComponentType.DROPDOWN,
            FilterComponentType.MULTI_DROPDOWN,
        ):
            continue

        @dash_app.callback(
            output=dict(options=Output(filter_id, "options")),
            inputs=dict(trigger=Input(filter_id, "id")),
        )
        def load_options(
            trigger,
            spec=filter_spec,
            factory=filter_factory,
            ds=data_service,
        ):
            try:
                return dict(
                    options=ds.get_distinct_values_with_labels(
                        field=spec.database_field,
                        dataset_type=factory.dataset_type,
                    )
                )
            except Exception as e:
                print(f"Error loading options for {spec.id}: {e}")
                return dict(options=[])


def _register_filter_store(
    dash_app: "Dash",
    prefix: str,
    filter_factory: FilterFactory,
) -> None:
    filter_inputs = filter_factory.create_callback_inputs()

    if not filter_inputs:
        return

    @dash_app.callback(
        output=dict(data=Output(f"{prefix}-filter-store", "data")),
        inputs=filter_inputs,
    )
    def update_filter_store(*filter_values):
        return dict(data=filter_factory.collect_filter_values(*filter_values))


def _register_button_states(dash_app: "Dash", prefix: str) -> None:
    @dash_app.callback(
        output=dict(
            update_disabled=Output(f"{prefix}-update-all-btn", "disabled"),
            save_disabled=Output(f"{prefix}-save-dashboard-btn", "disabled"),
        ),
        inputs=dict(
            chart_configs=Input(f"{prefix}-chart-configs-store", "data"),
        ),
    )
    def update_button_states(chart_configs):
        # Enable buttons if there are charts in configs
        has_charts = bool(chart_configs and len(chart_configs) > 0)
        print(f"[BUTTON_STATES] chart_configs keys: {list((chart_configs or {}).keys())}, has_charts: {has_charts}")

        return dict(update_disabled=not has_charts, save_disabled=not has_charts)


def _register_available_fields(
    dash_app: "Dash",
    prefix: str,
    filter_factory: FilterFactory,
) -> None:
    @dash_app.callback(
        output=dict(data=Output(f"{prefix}-available-fields", "data")),
        inputs=dict(collection_name=Input(f"{prefix}-collection-name", "data")),
    )
    def load_available_fields(collection_name):
        return dict(data=filter_factory.get_available_fields())


def _register_filter_specs(
    dash_app: "Dash",
    prefix: str,
    filter_factory: FilterFactory,
) -> None:
    @dash_app.callback(
        output=dict(data=Output(f"{prefix}-filter-specs", "data")),
        inputs=dict(collection_name=Input(f"{prefix}-collection-name", "data")),
    )
    def load_filter_specs(collection_name):
        return dict(data=filter_factory.get_filter_specs_for_modal())
