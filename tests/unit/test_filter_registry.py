"""Unit tests for FilterSpecRegistry classes.

Tests filter specification lookup through public APIs.
"""

import pytest

from sec_certs_page.dashboard.filters.registry import (
    CCFilterRegistry,
    FilterSpecRegistry,
    FIPSFilterRegistry,
    get_all_registries,
    get_filter_registry,
)
from sec_certs_page.dashboard.types.common import CollectionName
from sec_certs_page.dashboard.types.filter import FilterComponentType


class TestFilterSpecRegistryLookup:
    """Tests for FilterSpecRegistry lookup operations."""

    def test_get_all_filters_returns_non_empty_dict(self) -> None:
        """get_all_filters returns dictionary containing filter specs."""
        # Arrange & Act
        filters = CCFilterRegistry.get_all_filters()

        # Assert
        assert isinstance(filters, dict)
        assert len(filters) > 0

    def test_get_filter_with_valid_id_returns_filter_spec(self) -> None:
        """get_filter returns FilterSpec for existing filter ID."""
        # Arrange
        filter_id = "cc-category-filter"

        # Act
        result = CCFilterRegistry.get_filter(filter_id)

        # Assert
        assert result is not None
        assert result.id == filter_id

    def test_get_filter_with_invalid_id_returns_none(self) -> None:
        """get_filter returns None for non-existent filter ID."""
        # Arrange
        nonexistent_id = "nonexistent-filter"

        # Act
        result = CCFilterRegistry.get_filter(nonexistent_id)

        # Assert
        assert result is None

    def test_get_filter_with_empty_string_returns_none(self) -> None:
        """get_filter returns None for empty string filter ID."""
        # Arrange
        empty_id = ""

        # Act
        result = CCFilterRegistry.get_filter(empty_id)

        # Assert
        assert result is None

    def test_get_filters_by_component_type_returns_matching_filters(self) -> None:
        """get_filters_by_component_type returns only filters of specified type."""
        # Arrange
        target_type = FilterComponentType.MULTI_DROPDOWN

        # Act
        dropdowns = CCFilterRegistry.get_filters_by_component_type(target_type)

        # Assert
        assert len(dropdowns) > 0
        assert all(f.component_params.component_type == FilterComponentType.MULTI_DROPDOWN for f in dropdowns)


class TestCCFilterRegistry:
    """Tests for CCFilterRegistry specific filters."""

    def test_collection_type_is_common_criteria(self) -> None:
        """CCFilterRegistry has CommonCriteria as collection_name."""
        # Arrange & Act
        collection_name = CCFilterRegistry.collection_name

        # Assert
        assert collection_name == CollectionName.CommonCriteria

    def test_has_category_filter_with_correct_field(self) -> None:
        """CCFilterRegistry includes category filter mapping to 'category' field."""
        # Arrange & Act
        filter_spec = CCFilterRegistry.get_filter("cc-category-filter")

        # Assert
        assert filter_spec is not None
        assert filter_spec.database_field == "category"

    def test_has_scheme_filter_with_correct_field(self) -> None:
        """CCFilterRegistry includes scheme filter mapping to 'scheme' field."""
        # Arrange & Act
        filter_spec = CCFilterRegistry.get_filter("cc-scheme-filter")

        # Assert
        assert filter_spec is not None
        assert filter_spec.database_field == "scheme"

    def test_has_eal_filter_with_correct_field(self) -> None:
        """CCFilterRegistry includes EAL filter mapping to nested field."""
        # Arrange & Act
        filter_spec = CCFilterRegistry.get_filter("cc-eal-filter")

        # Assert
        assert filter_spec is not None
        assert filter_spec.database_field == "heuristics.eal"

    def test_has_year_filter_with_correct_field(self) -> None:
        """CCFilterRegistry includes year filter mapping to date field."""
        # Arrange & Act
        filter_spec = CCFilterRegistry.get_filter("cc-year-filter")

        # Assert
        assert filter_spec is not None
        assert filter_spec.database_field == "not_valid_before"

    def test_has_date_range_filters(self) -> None:
        """CCFilterRegistry includes both date range filters."""
        # Arrange & Act
        before_filter = CCFilterRegistry.get_filter("cc-not-valid-before-filter")
        after_filter = CCFilterRegistry.get_filter("cc-not-valid-after-filter")

        # Assert
        assert before_filter is not None
        assert after_filter is not None
        assert before_filter.component_params.component_type == FilterComponentType.DATE_PICKER


class TestFIPSFilterRegistry:
    """Tests for FIPSFilterRegistry specific filters."""

    def test_collection_type_is_fips140(self) -> None:
        """FIPSFilterRegistry has FIPS140 as collection_name."""
        # Arrange & Act
        collection_name = FIPSFilterRegistry.collection_name

        # Assert
        assert collection_name == CollectionName.FIPS140

    def test_has_level_filter_with_correct_field(self) -> None:
        """FIPSFilterRegistry includes security level filter."""
        # Arrange & Act
        filter_spec = FIPSFilterRegistry.get_filter("fips-level-filter")

        # Assert
        assert filter_spec is not None
        assert filter_spec.database_field == "web_data.level"

    def test_has_status_filter_with_correct_field(self) -> None:
        """FIPSFilterRegistry includes status filter."""
        # Arrange & Act
        filter_spec = FIPSFilterRegistry.get_filter("fips-status-filter")

        # Assert
        assert filter_spec is not None
        assert filter_spec.database_field == "web_data.status"

    def test_has_module_type_filter_with_correct_field(self) -> None:
        """FIPSFilterRegistry includes module type filter."""
        # Arrange & Act
        filter_spec = FIPSFilterRegistry.get_filter("fips-module-type-filter")

        # Assert
        assert filter_spec is not None
        assert filter_spec.database_field == "web_data.module_type"

    def test_has_standard_filter_with_correct_field(self) -> None:
        """FIPSFilterRegistry includes FIPS standard filter."""
        # Arrange & Act
        filter_spec = FIPSFilterRegistry.get_filter("fips-standard-filter")

        # Assert
        assert filter_spec is not None
        assert filter_spec.database_field == "web_data.standard"


class TestGetAllRegistries:
    """Tests for get_all_registries function."""

    def test_returns_list_of_registry_subclasses(self) -> None:
        """get_all_registries returns list of FilterSpecRegistry subclasses."""
        # Arrange & Act
        registries = get_all_registries()

        # Assert
        assert isinstance(registries, list)
        assert all(issubclass(r, FilterSpecRegistry) for r in registries)

    def test_includes_cc_registry(self) -> None:
        """get_all_registries includes CCFilterRegistry."""
        # Arrange & Act
        registries = get_all_registries()

        # Assert
        assert CCFilterRegistry in registries

    def test_includes_fips_registry(self) -> None:
        """get_all_registries includes FIPSFilterRegistry."""
        # Arrange & Act
        registries = get_all_registries()

        # Assert
        assert FIPSFilterRegistry in registries


class TestGetFilterRegistry:
    """Tests for get_filter_registry function."""

    def test_returns_cc_registry_for_common_criteria(self) -> None:
        """get_filter_registry returns CCFilterRegistry for CommonCriteria."""
        # Arrange
        collection = CollectionName.CommonCriteria

        # Act
        registry = get_filter_registry(collection)

        # Assert
        assert registry == CCFilterRegistry

    def test_returns_fips_registry_for_fips140(self) -> None:
        """get_filter_registry returns FIPSFilterRegistry for FIPS140."""
        # Arrange
        collection = CollectionName.FIPS140

        # Act
        registry = get_filter_registry(collection)

        # Assert
        assert registry == FIPSFilterRegistry


class TestFilterSpecStructure:
    """Tests validating FilterSpec structure and required fields."""

    @pytest.mark.parametrize("registry_class", [CCFilterRegistry, FIPSFilterRegistry])
    def test_all_filters_have_required_fields(self, registry_class: type[FilterSpecRegistry]) -> None:
        """All filters have id, database_field, and component_params."""
        # Arrange
        filters = registry_class.get_all_filters()

        # Act & Assert
        for filter_id, filter_spec in filters.items():
            assert filter_spec.id == filter_id, f"Filter ID mismatch: {filter_id}"
            assert filter_spec.database_field, f"Missing database_field: {filter_id}"
            assert filter_spec.component_params is not None, f"Missing component_params: {filter_id}"
            assert filter_spec.component_params.label, f"Missing label: {filter_id}"

    @pytest.mark.parametrize("registry_class", [CCFilterRegistry, FIPSFilterRegistry])
    def test_all_filters_have_valid_component_type(self, registry_class: type[FilterSpecRegistry]) -> None:
        """All filters have valid FilterComponentType enum value."""
        # Arrange
        filters = registry_class.get_all_filters()

        # Act & Assert
        for filter_id, filter_spec in filters.items():
            assert isinstance(
                filter_spec.component_params.component_type, FilterComponentType
            ), f"Invalid component_type: {filter_id}"

    @pytest.mark.parametrize("registry_class", [CCFilterRegistry, FIPSFilterRegistry])
    def test_filter_ids_are_unique(self, registry_class: type[FilterSpecRegistry]) -> None:
        """Filter IDs are unique within each registry."""
        # Arrange
        filters = registry_class.get_all_filters()
        filter_ids = list(filters.keys())

        # Act
        unique_ids = set(filter_ids)

        # Assert
        assert len(filter_ids) == len(unique_ids)
