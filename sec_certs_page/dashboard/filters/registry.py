from abc import ABC
from datetime import datetime
from typing import ClassVar

from ..dependencies import ComponentIDBuilder, FilterID
from ..filters.filter import FilterSpec
from ..types.common import CollectionName
from ..types.filter import FilterComponentParams, FilterComponentType, FilterOperator


class FilterSpecRegistry(ABC):
    """Abstract registry of filter specifications for a dataset type.

    Subclasses must define:
    - _filters: ClassVar[dict[str, FilterSpec]] - filter specifications
    - collection_name: ClassVar[CollectionType] - the collection this registry handles
    """

    _filters: ClassVar[dict[str, FilterSpec]] = {}
    collection_name: ClassVar[CollectionName]

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

    filter_id = ComponentIDBuilder(CollectionName.CommonCriteria)
    collection_name: ClassVar[CollectionName] = CollectionName.CommonCriteria
    _filters: ClassVar[dict[str, FilterSpec]] = {
        filter_id(FilterID.CATEGORY_FILTER): FilterSpec(
            id=filter_id(FilterID.CATEGORY_FILTER),
            database_field="category",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=FilterComponentParams(
                component_type=FilterComponentType.MULTI_DROPDOWN,
                label="Certificate Category",
                placeholder="Select categories...",
                multi=True,
                clearable=True,
                searchable=True,
                help_text="Filter certificates by product category",
            ),
        ),
        filter_id(FilterID.SCHEME_FILTER): FilterSpec(
            id=filter_id(FilterID.SCHEME_FILTER),
            database_field="scheme",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=FilterComponentParams(
                component_type=FilterComponentType.MULTI_DROPDOWN,
                label="Certification Scheme",
                placeholder="Select schemes...",
                multi=True,
                clearable=True,
                searchable=True,
                help_text="Filter by certification scheme/country",
            ),
        ),
        filter_id(FilterID.STATUS_FILTER): FilterSpec(
            id=filter_id(FilterID.STATUS_FILTER),
            database_field="status",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=FilterComponentParams(
                component_type=FilterComponentType.DROPDOWN,
                label="Certificate Status",
                placeholder="Select status...",
                clearable=True,
                searchable=True,
                help_text="Filter by certificate status (active/archived)",
            ),
        ),
        filter_id(FilterID.EAL_FILTER): FilterSpec(
            id=filter_id(FilterID.EAL_FILTER),
            database_field="heuristics.eal",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=FilterComponentParams(
                component_type=FilterComponentType.MULTI_DROPDOWN,
                label="Evaluation Assurance Level (EAL)",
                placeholder="Select EAL levels...",
                multi=True,
                clearable=True,
                searchable=True,
                help_text="Filter by EAL level (EAL1-EAL7)",
            ),
        ),
        filter_id(FilterID.YEAR_FILTER): FilterSpec(
            id=filter_id(FilterID.YEAR_FILTER),
            database_field="not_valid_before",
            operator=FilterOperator.YEAR_IN,
            data_type="int",
            component_params=FilterComponentParams(
                component_type=FilterComponentType.MULTI_DROPDOWN,
                label="Certificate Year",
                placeholder="Select years...",
                multi=True,
                clearable=True,
                searchable=True,
                help_text="Year when certificate was issued (extracted from certification date)",
            ),
        ),
        filter_id(FilterID.NOT_VALID_BEFORE_FILTER): FilterSpec(
            id=filter_id(FilterID.NOT_VALID_BEFORE_FILTER),
            database_field="not_valid_before",
            operator=FilterOperator.GTE,
            data_type="date",
            component_params=FilterComponentParams(
                component_type=FilterComponentType.DATE_PICKER,
                label="Certification Date From",
                placeholder="Select start date...",
                help_text="Minimum certification date (inclusive)",
            ),
            transform=lambda x: (x if isinstance(x, str) else x.isoformat() if isinstance(x, datetime) else str(x)),
        ),
        filter_id(FilterID.NOT_VALID_AFTER_FILTER): FilterSpec(
            id=filter_id(FilterID.NOT_VALID_AFTER_FILTER),
            database_field="not_valid_after",
            operator=FilterOperator.LTE,
            data_type="date",
            component_params=FilterComponentParams(
                component_type=FilterComponentType.DATE_PICKER,
                label="Certification Date To",
                placeholder="Select end date...",
                help_text="Maximum certification date (inclusive)",
            ),
            transform=lambda x: (x if isinstance(x, str) else x.isoformat() if isinstance(x, datetime) else str(x)),
        ),
        # Additional fields for chart grouping (not typically used as filters)
        filter_id(FilterID.VENDOR_FILTER): FilterSpec(
            id=filter_id(FilterID.VENDOR_FILTER),
            database_field="manufacturer",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=FilterComponentParams(
                component_type=FilterComponentType.MULTI_DROPDOWN,
                label="Vendor/Manufacturer",
                placeholder="Select vendors...",
                multi=True,
                clearable=True,
                searchable=True,
                help_text="Filter by certificate vendor/manufacturer",
            ),
        ),
        # CVE/Vulnerability filters
        filter_id(FilterID.HAS_CVES_FILTER): FilterSpec(
            id=filter_id(FilterID.HAS_CVES_FILTER),
            database_field="heuristics.related_cves._value.0",
            operator=FilterOperator.EXISTS,
            data_type="bool",
            data=[
                {"label": "Yes - Has CVEs", "value": True},
                {"label": "No - No CVEs", "value": False},
            ],
            component_params=FilterComponentParams(
                component_type=FilterComponentType.DROPDOWN,
                label="Has CVEs",
                placeholder="Any",
                clearable=True,
                help_text="Filter certificates with/without associated CVEs",
            ),
        ),
        filter_id(FilterID.HAS_TRANSITIVE_CVES_FILTER): FilterSpec(
            id=filter_id(FilterID.HAS_TRANSITIVE_CVES_FILTER),
            database_field="heuristics.direct_transitive_cves._value.0",
            operator=FilterOperator.EXISTS,
            data_type="bool",
            data=[
                {"label": "Yes - Has Transitive CVEs", "value": True},
                {"label": "No - No Transitive CVEs", "value": False},
            ],
            component_params=FilterComponentParams(
                component_type=FilterComponentType.DROPDOWN,
                label="Has Transitive CVEs",
                placeholder="Any",
                clearable=True,
                help_text="Filter certificates with/without transitive CVE exposure (through dependencies)",
            ),
        ),
    }


class FIPSFilterRegistry(FilterSpecRegistry):
    """FIPS 140 filter definitions."""

    filter_id = ComponentIDBuilder(CollectionName.FIPS140)
    collection_name: ClassVar[CollectionName] = CollectionName.FIPS140
    _filters: ClassVar[dict[str, FilterSpec]] = {
        filter_id(FilterID.LEVEL_FILTER): FilterSpec(
            id="fips-level-filter",
            database_field="web_data.level",
            operator=FilterOperator.IN,
            data_type="int",
            component_params=FilterComponentParams(
                component_type=FilterComponentType.MULTI_DROPDOWN,
                label="Security Level",
                placeholder="Select security levels...",
                multi=True,
                clearable=True,
                searchable=True,
                help_text="FIPS 140 security level (1-4)",
            ),
        ),
        filter_id(FilterID.STATUS_FILTER): FilterSpec(
            id="fips-status-filter",
            database_field="web_data.status",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=FilterComponentParams(
                component_type=FilterComponentType.DROPDOWN,
                label="Certificate Status",
                placeholder="Select status...",
                clearable=True,
                searchable=True,
                help_text="Current certificate status",
            ),
        ),
        filter_id(FilterID.MODULE_TYPE_FILTER): FilterSpec(
            id="fips-module-type-filter",
            database_field="web_data.module_type",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=FilterComponentParams(
                component_type=FilterComponentType.MULTI_DROPDOWN,
                label="Module Type",
                placeholder="Select module types...",
                multi=True,
                clearable=True,
                searchable=True,
                help_text="Type of cryptographic module",
            ),
        ),
        filter_id(FilterID.STANDARD_FILTER): FilterSpec(
            id="fips-standard-filter",
            database_field="web_data.standard",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=FilterComponentParams(
                component_type=FilterComponentType.MULTI_DROPDOWN,
                label="FIPS Standard",
                placeholder="Select standards...",
                multi=True,
                clearable=True,
                searchable=True,
                help_text="FIPS 140-1, 140-2, or 140-3",
            ),
        ),
        filter_id(FilterID.YEAR_FILTER): FilterSpec(
            id="fips-year-filter",
            database_field="web_data.date_validation",
            operator=FilterOperator.YEAR_IN,
            data_type="int",
            component_params=FilterComponentParams(
                component_type=FilterComponentType.MULTI_DROPDOWN,
                label="Validation Year",
                placeholder="Select years...",
                multi=True,
                clearable=True,
                searchable=True,
                help_text="Year when module was validated",
            ),
        ),
        filter_id(FilterID.VENDOR_FILTER): FilterSpec(
            id="fips-vendor-filter",
            database_field="web_data.vendor",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=FilterComponentParams(
                component_type=FilterComponentType.MULTI_DROPDOWN,
                label="Vendor",
                placeholder="Select vendors...",
                multi=True,
                clearable=True,
                searchable=True,
                help_text="Filter by module vendor",
            ),
        ),
        # CVE/Vulnerability filters
        filter_id(FilterID.HAS_CVES_FILTER): FilterSpec(
            id="fips-has-cves-filter",
            database_field="heuristics.related_cves._value.0",
            operator=FilterOperator.EXISTS,
            data_type="bool",
            data=[
                {"label": "Yes - Has CVEs", "value": True},
                {"label": "No - No CVEs", "value": False},
            ],
            component_params=FilterComponentParams(
                component_type=FilterComponentType.DROPDOWN,
                label="Has CVEs",
                placeholder="Any",
                clearable=True,
                help_text="Filter modules with/without associated CVEs",
            ),
        ),
    }


def get_all_registries() -> list[type[FilterSpecRegistry]]:
    """Get all registered FilterSpecRegistry subclasses.

    Automatically discovers all concrete subclasses of FilterSpecRegistry.
    """
    return list(FilterSpecRegistry.__subclasses__())


def get_filter_registry(collection_name: CollectionName) -> type[FilterSpecRegistry]:
    """Get the filter registry class for a dataset type."""
    for registry in get_all_registries():
        if registry.collection_name == collection_name:
            return registry
    supported = ", ".join(str(r.collection_name) for r in get_all_registries())
    raise ValueError(f"Unknown dataset type: {collection_name}. Supported: {supported}")
