from datetime import datetime
from typing import ClassVar

from ..filters.filter import FilterSpec
from ..types.common import CollectionName
from ..types.filter import DashFilterComponentParams, FilterComponentType, FilterOperator


class FilterSpecRegistry:
    """Immutable registry of filter specifications for a dataset type."""

    _filters: ClassVar[dict[str, FilterSpec]] = {}

    @classmethod
    def get_all_filters(cls) -> dict[str, FilterSpec]:
        """Get all filter specifications for this dataset type."""
        return cls._filters

    @classmethod
    def get_filter(cls, filter_id: str) -> FilterSpec | None:
        """Get a specific filter by ID, or None if not found."""
        return cls._filters.get(filter_id)

    @classmethod
    def get_filters_by_component_type(cls, component_type: FilterComponentType) -> list[FilterSpec]:
        """Get all filters of a specific component type."""
        return [f for f in cls._filters.values() if f.component_params.component_type == component_type]


class CCFilterRegistry(FilterSpecRegistry):
    """Common Criteria filter definitions."""

    _filters: ClassVar[dict[str, FilterSpec]] = {
        "cc-category-filter": FilterSpec(
            id="cc-category-filter",
            database_field="category",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=DashFilterComponentParams(
                component_type=FilterComponentType.MULTI_DROPDOWN,
                label="Certificate Category",
                placeholder="Select categories...",
                multi=True,
                clearable=True,
                searchable=True,
                help_text="Filter certificates by product category",
            ),
        ),
        "cc-scheme-filter": FilterSpec(
            id="cc-scheme-filter",
            database_field="scheme",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=DashFilterComponentParams(
                component_type=FilterComponentType.MULTI_DROPDOWN,
                label="Certification Scheme",
                placeholder="Select schemes...",
                multi=True,
                clearable=True,
                searchable=True,
                help_text="Filter by certification scheme/country",
            ),
        ),
        "cc-status-filter": FilterSpec(
            id="cc-status-filter",
            database_field="status",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=DashFilterComponentParams(
                component_type=FilterComponentType.MULTI_DROPDOWN,
                label="Certificate Status",
                placeholder="Select status...",
                multi=True,
                clearable=True,
                searchable=True,
                help_text="Filter by certificate status (active/archived)",
            ),
        ),
        "cc-not-valid-before-filter": FilterSpec(
            id="cc-not-valid-before-filter",
            database_field="not_valid_before",
            operator=FilterOperator.GTE,
            data_type="str",
            component_params=DashFilterComponentParams(
                component_type=FilterComponentType.DATE_PICKER,
                label="Certification Date From",
                placeholder="Select start date...",
                help_text="Minimum certification date (inclusive)",
            ),
            transform=lambda x: (x if isinstance(x, str) else x.isoformat() if isinstance(x, datetime) else str(x)),
        ),
        "cc-not-valid-after-filter": FilterSpec(
            id="cc-not-valid-after-filter",
            database_field="not_valid_after",
            operator=FilterOperator.LTE,
            data_type="str",
            component_params=DashFilterComponentParams(
                component_type=FilterComponentType.DATE_PICKER,
                label="Certification Date To",
                placeholder="Select end date...",
                help_text="Maximum certification date (inclusive)",
            ),
            transform=lambda x: (x if isinstance(x, str) else x.isoformat() if isinstance(x, datetime) else str(x)),
        ),
    }


class FIPSFilterRegistry(FilterSpecRegistry):
    """FIPS 140 filter definitions."""

    _filters: ClassVar[dict[str, FilterSpec]] = {
        "fips-level-filter": FilterSpec(
            id="fips-level-filter",
            database_field="web_data.level",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=DashFilterComponentParams(
                component_type=FilterComponentType.MULTI_DROPDOWN,
                label="Security Level",
                placeholder="Select security levels...",
                multi=True,
                clearable=True,
                searchable=True,
                help_text="FIPS 140 security level (1-4)",
            ),
        ),
        "fips-status-filter": FilterSpec(
            id="fips-status-filter",
            database_field="web_data.status",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=DashFilterComponentParams(
                component_type=FilterComponentType.MULTI_DROPDOWN,
                label="Certificate Status",
                placeholder="Select status...",
                multi=True,
                clearable=True,
                searchable=True,
                help_text="Current certificate status",
            ),
        ),
        "fips-module-type-filter": FilterSpec(
            id="fips-module-type-filter",
            database_field="web_data.module_type",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=DashFilterComponentParams(
                component_type=FilterComponentType.MULTI_DROPDOWN,
                label="Module Type",
                placeholder="Select module types...",
                multi=True,
                clearable=True,
                searchable=True,
                help_text="Type of cryptographic module",
            ),
        ),
        "fips-standard-filter": FilterSpec(
            id="fips-standard-filter",
            database_field="web_data.standard",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=DashFilterComponentParams(
                component_type=FilterComponentType.MULTI_DROPDOWN,
                label="FIPS Standard",
                placeholder="Select standards...",
                multi=True,
                clearable=True,
                searchable=True,
                help_text="FIPS 140-1, 140-2, or 140-3",
            ),
        ),
    }


_REGISTRY_MAP: dict[CollectionName, type[FilterSpecRegistry]] = {
    CollectionName.CommonCriteria: CCFilterRegistry,
    CollectionName.FIPS140: FIPSFilterRegistry,
}


def get_filter_registry(dataset_type: CollectionName) -> type[FilterSpecRegistry]:
    """Get the filter registry class for a dataset type."""
    if dataset_type not in _REGISTRY_MAP:
        supported = ", ".join(str(t) for t in _REGISTRY_MAP.keys())
        raise ValueError(f"Unknown dataset type: {dataset_type}. Supported: {supported}")
    return _REGISTRY_MAP[dataset_type]
