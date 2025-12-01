from typing import TYPE_CHECKING

from dash.dependencies import Input, Output, State

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
    _register_filter_options(dash_app, prefix, filter_factory, data_service)
    _register_filter_store(dash_app, prefix, filter_factory)
    _register_button_states(dash_app, prefix)
    _register_metadata(dash_app, prefix, filter_factory)


def _register_filter_options(
    dash_app: "Dash",
    prefix: str,
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
            inputs=dict(dashboard_loaded=Input(f"{prefix}-dashboard-loaded", "data")),
            prevent_initial_call=True,
        )
        def load_options(
            dashboard_loaded,
            spec=filter_spec,
            factory=filter_factory,
            ds=data_service,
        ):
            if not dashboard_loaded:
                return dict(options=[])
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


def _register_metadata(
    dash_app: "Dash",
    prefix: str,
    filter_factory: FilterFactory,
) -> None:
    """Combined callback for available fields and filter specs - reduces initial calls."""

    @dash_app.callback(
        output=dict(
            available_fields=Output(f"{prefix}-available-fields", "data"),
            filter_specs=Output(f"{prefix}-filter-specs", "data"),
            metadata_loaded=Output(f"{prefix}-metadata-loaded", "data"),
        ),
        inputs=dict(modal_open=Input(f"{prefix}-create-chart-modal", "is_open")),
        state=dict(already_loaded=State(f"{prefix}-metadata-loaded", "data")),
        prevent_initial_call=True,
    )
    def load_metadata(modal_open, already_loaded):
        """Load metadata only when modal opens for the first time - lazy loading optimization."""
        from dash import no_update

        # Don't do anything when modal closes
        if not modal_open:
            return dict(available_fields=no_update, filter_specs=no_update, metadata_loaded=no_update)

        # If already loaded, don't reload
        if already_loaded:
            return dict(available_fields=no_update, filter_specs=no_update, metadata_loaded=no_update)

        return dict(
            available_fields=filter_factory.get_available_fields(),
            filter_specs=filter_factory.get_filter_specs_for_modal(),
            metadata_loaded=True,
        )
