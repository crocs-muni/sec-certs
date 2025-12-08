import logging
from typing import TYPE_CHECKING

from dash import no_update
from dash.dependencies import Input, Output, State

from sec_certs_page.dashboard.dependencies import ComponentID, ComponentIDBuilder

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
    component_id = ComponentIDBuilder(collection_name)
    for filter_id, filter_spec in filter_factory.registry.get_all_filters().items():
        if filter_spec.component_params.component_type not in (
            FilterComponentType.DROPDOWN,
            FilterComponentType.MULTI_DROPDOWN,
        ):
            continue

        @dash_app.callback(
            output=dict(options=Output(filter_id, "options")),
            inputs=dict(dashboard_loaded=Input(component_id(ComponentID.DASHBOARD_LOADED), "data")),
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
            except Exception:
                error_message = f"[LOAD_OPTIONS] Error loading options for {spec.id}"
                logger.exception(error_message)
                return dict(options=[])


def _register_filter_store(
    dash_app: "Dash",
    collection_name: CollectionName,
    filter_factory: FilterFactory,
) -> None:
    filter_inputs = filter_factory.create_callback_inputs()

    if not filter_inputs:
        return

    component_id = ComponentIDBuilder(collection_name)

    @dash_app.callback(
        output=dict(data=Output(component_id(ComponentID.FILTER_STORE), "data")),
        inputs=filter_inputs,
    )
    def update_filter_store(*filter_values):
        return dict(data=filter_factory.collect_filter_values(*filter_values))


def _register_button_states(dash_app: "Dash", collection_name: CollectionName) -> None:
    component_id = ComponentIDBuilder(collection_name)

    @dash_app.callback(
        output=dict(
            update_disabled=Output(component_id(ComponentID.UPDATE_ALL_BTN), "disabled"),
            save_disabled=Output(component_id(ComponentID.SAVE_DASHBOARD_BTN), "disabled"),
        ),
        inputs=dict(
            chart_configs=Input(component_id(ComponentID.CHART_CONFIGS_STORE), "data"),
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
    component_id = ComponentIDBuilder(collection_name)

    @dash_app.callback(
        output=dict(
            available_fields=Output(component_id(ComponentID.AVAILABLE_FIELDS), "data"),
            filter_specs=Output(component_id(ComponentID.FILTER_SPECS), "data"),
            metadata_loaded=Output(component_id(ComponentID.METADATA_LOADED), "data"),
        ),
        inputs=dict(modal_open=Input(component_id(ComponentID.CREATE_CHART_MODAL), "is_open")),
        state=dict(already_loaded=State(component_id(ComponentID.METADATA_LOADED), "data")),
        prevent_initial_call=True,
    )
    def load_metadata(modal_open, already_loaded):
        """Load metadata only when modal opens for the first time - lazy loading optimization."""

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
