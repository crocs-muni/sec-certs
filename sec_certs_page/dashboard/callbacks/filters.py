import logging
from typing import TYPE_CHECKING

from dash.dependencies import Input, Output, State

from ..filters.factory import FilterFactory
from ..types.common import CollectionName
from ..types.filter import FilterComponentType

if TYPE_CHECKING:
    from ..base import Dash
    from ..data import DataService

logger = logging.getLogger(__name__)


def register_filter_callbacks(
    dash_app: "Dash",
    collection_name: CollectionName,
    filter_factory: FilterFactory,
    data_service: "DataService",
) -> None:
    _register_filter_options(dash_app, collection_name, filter_factory, data_service)
    _register_filter_store(dash_app, collection_name, filter_factory)
    _register_button_states(dash_app, collection_name)
    _register_metadata(dash_app, collection_name, filter_factory)


def _register_filter_options(
    dash_app: "Dash",
    collection_name: CollectionName,
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
            inputs=dict(dashboard_loaded=Input(f"{collection_name}-dashboard-loaded", "data")),
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
                        collection_name=factory.collection_name,
                    )
                )
            except Exception as e:
                print(f"Error loading options for {spec.id}: {e}")
                return dict(options=[])


def _register_filter_store(
    dash_app: "Dash",
    collection_name: CollectionName,
    filter_factory: FilterFactory,
) -> None:
    filter_inputs = filter_factory.create_callback_inputs()

    if not filter_inputs:
        return

    @dash_app.callback(
        output=dict(data=Output(f"{collection_name}-filter-store", "data")),
        inputs=filter_inputs,
    )
    def update_filter_store(*filter_values):
        return dict(data=filter_factory.collect_filter_values(*filter_values))


def _register_button_states(dash_app: "Dash", collection_name: CollectionName) -> None:
    @dash_app.callback(
        output=dict(
            update_disabled=Output(f"{collection_name}-update-all-btn", "disabled"),
            save_disabled=Output(f"{collection_name}-save-dashboard-btn", "disabled"),
        ),
        inputs=dict(
            chart_configs=Input(f"{collection_name}-chart-configs-store", "data"),
        ),
    )
    def update_button_states(chart_configs):
        # Enable buttons if there are charts in configs
        has_charts = bool(chart_configs and len(chart_configs) > 0)
        logger.debug(
            f"[BUTTON_STATES] chart_configs keys: {list((chart_configs or {}).keys())}, has_charts: {has_charts}"
        )
        logger.debug(f"[BUTTON_STATES] update_disabled: {not has_charts}, save_disabled: {not has_charts}")

        return dict(update_disabled=not has_charts, save_disabled=not has_charts)


def _register_metadata(
    dash_app: "Dash",
    collection_name: CollectionName,
    filter_factory: FilterFactory,
) -> None:
    """Combined callback for available fields and filter specs - reduces initial calls."""

    @dash_app.callback(
        output=dict(
            available_fields=Output(f"{collection_name}-available-fields", "data"),
            filter_specs=Output(f"{collection_name}-filter-specs", "data"),
            metadata_loaded=Output(f"{collection_name}-metadata-loaded", "data"),
        ),
        inputs=dict(modal_open=Input(f"{collection_name}-create-chart-modal", "is_open")),
        state=dict(already_loaded=State(f"{collection_name}-metadata-loaded", "data")),
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
