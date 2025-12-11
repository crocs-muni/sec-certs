from typing import Any

import dash_bootstrap_components as dbc
import pytest
from dash import dcc, html

from sec_certs_page.dashboard.filters.factory import FilterFactory
from sec_certs_page.dashboard.filters.filter import FilterSpec
from sec_certs_page.dashboard.types.common import CollectionName
from sec_certs_page.dashboard.types.filter import FilterComponentParams, FilterComponentType, FilterOperator


class TestFilterFactoryCreateFilter:
    """Tests for FilterFactory.create_filter public API."""

    @pytest.fixture
    def cc_factory(self) -> FilterFactory:
        """Create a FilterFactory for CommonCriteria."""
        return FilterFactory(CollectionName.CommonCriteria)

    def test_create_filter_dropdown_returns_dropdown_component(self, cc_factory: FilterFactory) -> None:
        """create_filter returns dcc.Dropdown for DROPDOWN type."""
        spec = FilterSpec(
            id="test-dropdown",
            database_field="category",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=FilterComponentParams(
                label="Category",
                component_type=FilterComponentType.DROPDOWN,
                placeholder="Select category...",
            ),
            data=["ICs", "Software", "Network"],
        )

        component = cc_factory.create_filter(spec, with_label=False)

        assert isinstance(component, dcc.Dropdown)

    def test_create_filter_dropdown_with_label_wraps_in_div(self, cc_factory: FilterFactory) -> None:
        """create_filter with with_label=True wraps dropdown in labeled Div."""
        spec = FilterSpec(
            id="test-dropdown",
            database_field="category",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=FilterComponentParams(
                label="Category",
                component_type=FilterComponentType.DROPDOWN,
            ),
            data=["ICs", "Software"],
        )

        component = cc_factory.create_filter(spec, with_label=True)

        assert isinstance(component, html.Div)
        assert isinstance(component.children[0], dbc.Label)
        assert isinstance(component.children[1], dcc.Dropdown)

    def test_create_filter_multi_dropdown_sets_multi_true(self, cc_factory: FilterFactory) -> None:
        """create_filter returns multi-select dropdown for MULTI_DROPDOWN type."""
        spec = FilterSpec(
            id="test-multi-dropdown",
            database_field="scheme",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=FilterComponentParams(
                label="Scheme",
                component_type=FilterComponentType.MULTI_DROPDOWN,
            ),
            data=["DE", "FR", "US"],
        )

        component = cc_factory.create_filter(spec, with_label=False)

        assert isinstance(component, dcc.Dropdown)
        assert component.multi is True

    def test_create_filter_date_range_returns_date_picker_range(self, cc_factory: FilterFactory) -> None:
        """create_filter returns DatePickerRange for DATE_RANGE type."""
        spec = FilterSpec(
            id="test-date-range",
            database_field="not_valid_before",
            operator=FilterOperator.GTE,
            data_type="date",
            component_params=FilterComponentParams(
                label="Valid From",
                component_type=FilterComponentType.DATE_RANGE,
                min_value="2000-01-01",
                max_value="2025-12-31",
            ),
        )

        component = cc_factory.create_filter(spec, with_label=False)

        assert isinstance(component, dcc.DatePickerRange)

    def test_create_filter_date_picker_returns_date_picker_single(self, cc_factory: FilterFactory) -> None:
        """create_filter returns DatePickerSingle for DATE_PICKER type."""
        spec = FilterSpec(
            id="test-date-picker",
            database_field="certification_date",
            operator=FilterOperator.EQ,
            data_type="date",
            component_params=FilterComponentParams(
                label="Certification Date",
                component_type=FilterComponentType.DATE_PICKER,
            ),
        )

        component = cc_factory.create_filter(spec, with_label=False)

        assert isinstance(component, dcc.DatePickerSingle)

    def test_create_filter_text_search_returns_input(self, cc_factory: FilterFactory) -> None:
        """create_filter returns dbc.Input for TEXT_SEARCH type."""
        spec = FilterSpec(
            id="test-text-search",
            database_field="name",
            operator=FilterOperator.REGEX,
            data_type="str",
            component_params=FilterComponentParams(
                label="Certificate Name",
                component_type=FilterComponentType.TEXT_SEARCH,
                placeholder="Search by name...",
            ),
        )

        component = cc_factory.create_filter(spec, with_label=False)

        assert isinstance(component, dbc.Input)
        assert component.type == "text"

    def test_create_filter_checkbox_returns_checkbox(self, cc_factory: FilterFactory) -> None:
        """create_filter returns dbc.Checkbox for CHECKBOX type."""
        spec = FilterSpec(
            id="test-checkbox",
            database_field="is_active",
            operator=FilterOperator.EQ,
            data_type="bool",
            component_params=FilterComponentParams(
                label="Active Only",
                component_type=FilterComponentType.CHECKBOX,
                default_value=False,
            ),
        )

        component = cc_factory.create_filter(spec, with_label=True)

        assert isinstance(component, dbc.Checkbox)

    def test_create_filter_dropdown_builds_options_from_data(self, cc_factory: FilterFactory) -> None:
        """create_filter builds dropdown options from filter data."""
        spec = FilterSpec(
            id="test-options",
            database_field="field",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=FilterComponentParams(
                label="Options",
                component_type=FilterComponentType.DROPDOWN,
            ),
            data=["Option A", "Option B", "Option C"],
        )

        component = cc_factory.create_filter(spec, with_label=False)

        assert len(component.options) == 3
        assert component.options[0] == {"label": "Option A", "value": "Option A"}

    def test_create_filter_generates_correct_component_id(self, cc_factory: FilterFactory) -> None:
        """create_filter generates component ID with dataset prefix."""
        spec = FilterSpec(
            id="category-filter",
            database_field="category",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=FilterComponentParams(
                label="Category",
                component_type=FilterComponentType.DROPDOWN,
            ),
        )

        component = cc_factory.create_filter(spec, with_label=False)

        expected_id = f"{cc_factory.collection_name.value}-filter-category-filter"
        assert component.id == expected_id


class TestFilterFactoryCreateFilterEdgeCases:
    """Tests for FilterFactory.create_filter edge cases."""

    @pytest.fixture
    def cc_factory(self) -> FilterFactory:
        """Create a FilterFactory for CommonCriteria."""
        return FilterFactory(CollectionName.CommonCriteria)

    def test_create_filter_unknown_type_returns_error_span(self, cc_factory: FilterFactory) -> None:
        """create_filter returns error span for unrecognized filter type."""
        spec = FilterSpec(
            id="unknown-filter",
            database_field="field",
            operator=FilterOperator.EQ,
            data_type="str",
            component_params=FilterComponentParams(
                label="Unknown",
                component_type=FilterComponentType.DROPDOWN,
            ),
        )
        spec.component_params.component_type = "invalid_type"  # type: ignore[assignment]

        component = cc_factory.create_filter(spec, with_label=False)

        assert isinstance(component, html.Span)
        assert "Unknown filter type" in str(component.children)

    @pytest.mark.parametrize("data", [[], None])
    def test_create_filter_dropdown_empty_data_returns_empty_options(
        self, cc_factory: FilterFactory, data: list[str] | None
    ) -> None:
        """create_filter returns dropdown with empty options when data is empty or None."""
        spec = FilterSpec(
            id="empty-data",
            database_field="field",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=FilterComponentParams(
                label="Empty",
                component_type=FilterComponentType.DROPDOWN,
            ),
            data=data,
        )

        component = cc_factory.create_filter(spec, with_label=False)

        assert isinstance(component, dcc.Dropdown)
        assert component.options == []

    def test_create_filter_dropdown_mixed_types_converts_to_strings(self, cc_factory: FilterFactory) -> None:
        """create_filter converts mixed data types to string labels."""
        spec = FilterSpec(
            id="mixed-data",
            database_field="field",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=FilterComponentParams(
                label="Mixed",
                component_type=FilterComponentType.DROPDOWN,
            ),
            data=[1, "two", 3.0, None],
        )

        component = cc_factory.create_filter(spec, with_label=False)

        assert len(component.options) == 4
        assert component.options[0]["label"] == "1"
        assert component.options[1]["label"] == "two"
        assert component.options[2]["label"] == "3.0"
        assert component.options[3]["label"] == "None"

    def test_create_filter_with_help_text_includes_small_element(self, cc_factory: FilterFactory) -> None:
        """create_filter includes help text as Small element."""
        spec = FilterSpec(
            id="help-filter",
            database_field="field",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=FilterComponentParams(
                label="With Help",
                component_type=FilterComponentType.DROPDOWN,
                help_text="This is helpful information",
            ),
        )

        component = cc_factory.create_filter(spec, with_label=True)

        assert isinstance(component, html.Div)
        assert len(component.children) == 3
        assert isinstance(component.children[2], html.Small)

    @pytest.mark.parametrize(
        "component_type,expected_prefix",
        [
            (FilterComponentType.DROPDOWN, "Select"),
            (FilterComponentType.TEXT_SEARCH, "Search"),
        ],
    )
    def test_create_filter_generates_placeholder_when_not_provided(
        self, cc_factory: FilterFactory, component_type: FilterComponentType, expected_prefix: str
    ) -> None:
        """create_filter generates placeholder from label when not provided."""
        spec = FilterSpec(
            id="no-placeholder",
            database_field="field",
            operator=FilterOperator.IN if component_type == FilterComponentType.DROPDOWN else FilterOperator.REGEX,
            data_type="str",
            component_params=FilterComponentParams(
                label="MyLabel",
                component_type=component_type,
                placeholder=None,
            ),
        )

        component = cc_factory.create_filter(spec, with_label=False)

        assert component.placeholder == f"{expected_prefix} MyLabel..."


class TestFilterFactoryCollectFilterValues:
    """Tests for FilterFactory.collect_filter_values public API."""

    @pytest.fixture
    def cc_factory(self) -> FilterFactory:
        """Create a FilterFactory for CommonCriteria."""
        return FilterFactory(CollectionName.CommonCriteria)

    def test_collect_filter_values_pairs_ids_with_values(self, cc_factory: FilterFactory) -> None:
        """collect_filter_values creates dict mapping filter IDs to values."""
        filter_ids = cc_factory.get_filter_ids()
        if len(filter_ids) < 2:
            pytest.skip("Not enough filters registered")
        values: list[Any] = ["test_value", None] + [None] * (len(filter_ids) - 2)

        result = cc_factory.collect_filter_values(*values)

        assert filter_ids[0] in result
        assert result[filter_ids[0]] == "test_value"
        assert filter_ids[1] not in result

    def test_collect_filter_values_excludes_empty_string(self, cc_factory: FilterFactory) -> None:
        """collect_filter_values excludes empty string values."""
        filter_ids = cc_factory.get_filter_ids()
        if not filter_ids:
            pytest.skip("No filters registered")
        values: list[Any] = [""] + [None] * (len(filter_ids) - 1)

        result = cc_factory.collect_filter_values(*values)

        assert filter_ids[0] not in result

    def test_collect_filter_values_excludes_empty_list(self, cc_factory: FilterFactory) -> None:
        """collect_filter_values excludes empty list values."""
        filter_ids = cc_factory.get_filter_ids()
        if not filter_ids:
            pytest.skip("No filters registered")
        values: list[Any] = [[]] + [None] * (len(filter_ids) - 1)

        result = cc_factory.collect_filter_values(*values)

        assert filter_ids[0] not in result

    def test_collect_filter_values_excludes_none(self, cc_factory: FilterFactory) -> None:
        """collect_filter_values excludes None values."""
        filter_ids = cc_factory.get_filter_ids()
        if not filter_ids:
            pytest.skip("No filters registered")
        values: list[Any] = [None] * len(filter_ids)

        result = cc_factory.collect_filter_values(*values)

        assert len(result) == 0

    def test_collect_filter_values_includes_zero(self, cc_factory: FilterFactory) -> None:
        """collect_filter_values includes zero as valid value."""
        filter_ids = cc_factory.get_filter_ids()
        if not filter_ids:
            pytest.skip("No filters registered")
        values: list[Any] = [0] + [None] * (len(filter_ids) - 1)

        result = cc_factory.collect_filter_values(*values)

        assert filter_ids[0] in result
        assert result[filter_ids[0]] == 0

    def test_collect_filter_values_includes_false(self, cc_factory: FilterFactory) -> None:
        """collect_filter_values includes False as valid checkbox value."""
        filter_ids = cc_factory.get_filter_ids()
        if not filter_ids:
            pytest.skip("No filters registered")
        values: list[Any] = [False] + [None] * (len(filter_ids) - 1)

        result = cc_factory.collect_filter_values(*values)

        assert filter_ids[0] in result
        assert result[filter_ids[0]] is False


class TestFilterFactoryGetAvailableFields:
    """Tests for FilterFactory.get_available_fields public API."""

    def test_get_available_fields_cc_includes_year_from(self) -> None:
        """get_available_fields for CC includes derived field year_from."""
        factory = FilterFactory(CollectionName.CommonCriteria)

        fields = factory.get_available_fields()

        field_values = [f["value"] for f in fields]
        assert "year_from" in field_values

    def test_get_available_fields_returns_dict_structure(self) -> None:
        """get_available_fields returns list of dicts with label, value, data_type."""
        factory = FilterFactory(CollectionName.CommonCriteria)

        fields = factory.get_available_fields()

        assert all("label" in f and "value" in f and "data_type" in f for f in fields)

    def test_get_available_fields_cc_and_fips_differ(self) -> None:
        """get_available_fields returns different fields for CC vs FIPS."""
        cc_factory = FilterFactory(CollectionName.CommonCriteria)
        fips_factory = FilterFactory(CollectionName.FIPS140)

        cc_fields = cc_factory.get_available_fields()
        fips_fields = fips_factory.get_available_fields()

        cc_values = {f["value"] for f in cc_fields}
        fips_values = {f["value"] for f in fips_fields}
        assert cc_values != fips_values


class TestFilterFactoryCreateFilterPanel:
    """Tests for FilterFactory.create_filter_panel public API."""

    def test_create_filter_panel_returns_card(self) -> None:
        """create_filter_panel returns dbc.Card component."""
        factory = FilterFactory(CollectionName.CommonCriteria)

        panel = factory.create_filter_panel()

        assert isinstance(panel, dbc.Card)
