import logging
from datetime import datetime
from logging import Logger
from typing import TYPE_CHECKING, Any, Protocol, TypeVar

from sec_certs_page.dashboard.types.common import DatasetType
from sec_certs_page.dashboard.types.filters import FilterOperator, FilterSpec, FilterUIType, UIMetadata

if TYPE_CHECKING:
    from sec_certs_page.dashboard.data import DataService

logger: Logger = logging.getLogger(__name__)


TFilterRegistry = TypeVar("TFilterRegistry", bound="FilterRegistryInterface")


class FilterRegistryInterface(Protocol):
    _filters: dict[str, FilterSpec]
    _initialized: bool

    @classmethod
    def get_filter_definition(cls, filter_id: str) -> FilterSpec | None: ...
    @classmethod
    def get_all_filters(cls) -> dict[str, FilterSpec]: ...
    @classmethod
    def get_filters_by_ui_type(cls, ui_type: FilterUIType) -> list[FilterSpec]: ...


class CCFilterRegistry(FilterRegistryInterface):
    """Unified registry for all filter definitions."""

    _initialized: bool = False
    _filters = {
        "category-filter": FilterSpec(
            id="category-filter",
            mongodb_field="category",
            operator=FilterOperator.IN,
            data_type=str,
            ui_metadata=UIMetadata(
                ui_type=FilterUIType.MULTI_DROPDOWN,
                label="Certificate Category",
                placeholder="Select categories...",
                options=None,
                multi=True,
                clearable=True,
                searchable=True,
                help_text="Filter certificates by product category",
            ),
            lazy_load_options=True,
        ),
        "scheme-filter": FilterSpec(
            id="scheme-filter",
            mongodb_field="scheme",
            operator=FilterOperator.IN,
            data_type=str,
            ui_metadata=UIMetadata(
                ui_type=FilterUIType.MULTI_DROPDOWN,
                label="Certification Scheme",
                placeholder="Select schemes...",
                options=None,  # Will be loaded from database
                multi=True,
                clearable=True,
                searchable=True,
                help_text="Filter by certification scheme/country",
            ),
            lazy_load_options=True,
            label_map={
                "AU": "Australia (AU)",
                "CA": "Canada (CA)",
                "FR": "France (FR)",
                "DE": "Germany (DE)",
                "IN": "India (IN)",
                "IT": "Italy (IT)",
                "JP": "Japan (JP)",
                "MY": "Malaysia (MY)",
                "NL": "Netherlands (NL)",
                "NO": "Norway (NO)",
                "KR": "South Korea (KR)",
                "PL": "Poland (PL)",
                "SG": "Singapore (SG)",
                "ES": "Spain (ES)",
                "SE": "Sweden (SE)",
                "TR": "Turkey (TR)",
                "US": "United States (US)",
            },
        ),
        "not-valid-before-filter": FilterSpec(
            id="not-valid-before-filter",
            mongodb_field="not_valid_before",
            operator=FilterOperator.GTE,
            data_type=str,
            ui_metadata=UIMetadata(
                ui_type=FilterUIType.DATE_PICKER,
                label="Certification Date From",
                placeholder="Select start date...",
                help_text="Minimum certification date (inclusive)",
            ),
            transform=lambda x: x if isinstance(x, str) else x.isoformat() if isinstance(x, datetime) else str(x),
        ),
        "not-valid-after-filter": FilterSpec(
            id="not-valid-after-filter",
            mongodb_field="not_valid_after",
            operator=FilterOperator.LTE,
            data_type=str,
            ui_metadata=UIMetadata(
                ui_type=FilterUIType.DATE_PICKER,
                label="Certification Date To",
                placeholder="Select end date...",
                help_text="Maximum certification date (inclusive)",
            ),
            transform=lambda x: x if isinstance(x, str) else x.isoformat() if isinstance(x, datetime) else str(x),
        ),
    }

    @classmethod
    def initialize_filters(cls, filter_options: dict[str, list | dict[str, Any] | None]) -> None:
        """Initialize filters with dynamic options from database.

        This should be called only when requesting the data from the database for the first time.

        :param data_service: DataService instance for querying MongoDB
        """
        if cls._initialized:
            return

        for filter_id, options in filter_options.items():
            filter_spec = cls._filters.get(filter_id)
            if filter_spec and options is not None:
                filter_spec.ui_metadata.options = options

        cls._initialized = True

    @classmethod
    def get_filter_definition(cls, filter_id: str) -> FilterSpec | None:
        """Get filter specification by ID.

        :param filter_id: Filter identifier
        :return: FilterSpec or None if not found
        """
        return CCFilterRegistry._filters.get(filter_id)

    @classmethod
    def get_all_filters(cls) -> dict[str, FilterSpec]:
        """Get all filter specifications for a dataset type."""
        return CCFilterRegistry._filters

    @classmethod
    def get_filters_by_ui_type(cls, ui_type: FilterUIType) -> list[FilterSpec]:
        """Get all filters of a specific UI type.

        Useful for grouping filters in UI (e.g., all dropdowns together).

        :param ui_type: Type of UI component
        :param dataset_type: Dataset type ('cc' or 'fips')
        :return: List of filter specifications matching UI type
        """
        all_filters = cls.get_all_filters()
        return [f for f in all_filters.values() if f.ui_metadata.ui_type == ui_type]


class FIPSFilterRegistry(FilterRegistryInterface):
    """Unified registry for FIPS filter definitions."""

    _filters: dict[str, FilterSpec] = {
        "level-filter": FilterSpec(
            id="level-filter",
            mongodb_field="web_data.level",
            operator=FilterOperator.IN,
            data_type=str,
            ui_metadata=UIMetadata(
                ui_type=FilterUIType.MULTI_DROPDOWN,
                label="Security Level",
                placeholder="Select security levels...",
                options=None,  # Will be loaded from database
                multi=True,
                clearable=True,
                searchable=True,
                help_text="FIPS 140 security level (1-4)",
            ),
            lazy_load_options=True,
        ),
        "status-filter": FilterSpec(
            id="status-filter",
            mongodb_field="web_data.status",
            operator=FilterOperator.IN,
            data_type=str,
            ui_metadata=UIMetadata(
                ui_type=FilterUIType.MULTI_DROPDOWN,
                label="Certificate Status",
                placeholder="Select status...",
                options=None,  # Will be loaded from database
                multi=True,
                clearable=True,
                searchable=True,
                help_text="Current certificate status",
            ),
            lazy_load_options=True,
        ),
    }


class FilterRegistryFactory:
    """Factory class for creating filter registries based on dataset type."""

    _registry_map: dict[str, type[FilterRegistryInterface]] = {
        "cc": CCFilterRegistry,
        "fips": FIPSFilterRegistry,
    }

    def __init__(self, data_service: DataService):
        self.data_service = data_service

    def _load_filter_options(self, dataset_type: DatasetType) -> None:
        """Load options for all filters of the cc dataset."""
        if self.data_service is None:
            raise RuntimeError("FilterRegistry not initialized with DataService")

        for filter in self._registry_map[dataset_type]._filters.values():
            if filter.lazy_load_options and filter.ui_metadata.options is None:
                try:
                    filter.ui_metadata.options = self.data_service.get_distinct_values_with_labels(
                        field=filter.mongodb_field,
                        dataset_type=dataset_type,
                        label_map=filter.label_map,
                    )
                except Exception as e:
                    logging.getLogger(__name__).warning(f"Failed to load options for {filter.id}: {e}")
                    filter.ui_metadata.options = []

    @classmethod
    def get_registry(cls, dataset_type: DatasetType) -> type[FilterRegistryInterface]:
        """
        Get the appropriate filter registry class for the given dataset type.

        :param dataset_type: Type of dataset ("cc" or "fips")
        :return: The corresponding filter registry class
        :raises ValueError: If dataset_type is not supported
        """
        if dataset_type not in cls._registry_map:
            raise ValueError(f"Unknown dataset type: {dataset_type}. Supported types: {list(cls._registry_map.keys())}")
        return cls._registry_map[dataset_type]

    @classmethod
    def create_registry(cls, dataset_type: DatasetType) -> FilterRegistryInterface:
        """
        Create an instance of the appropriate filter registry.

        :param dataset_type: Type of dataset ("cc" or "fips")
        :return: An instance of the corresponding filter registry
        """
        registry_class = cls.get_registry(dataset_type)
        return registry_class()
