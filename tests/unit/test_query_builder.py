"""Unit tests for QueryBuilder query generation and derived-field resolution.

Pure unit tests (no MongoDB or fixtures). They exercise the public
``build_query_from_filters`` API and the public ``resolve_derived_field`` dispatch,
covering the FIPS ``web_data.validation_history`` array special-case and the
collection-specific year extraction.
"""

from sec_certs_page.dashboard.filters.query_builder import build_query_from_filters, resolve_derived_field
from sec_certs_page.dashboard.types.common import CollectionName

# Expected contract values, written as literals so the tests pin them independently
# of the production constants.
_VALIDATION_HISTORY = "web_data.validation_history"


class TestYearInQueryGeneration:
    """YEAR_IN generation through the public build_query_from_filters API.

    These drive the real registries, so they also guard against a regression where
    a year filter points at the wrong database_field (the bug that motivated this
    change). The returned MongoDB query dict is the builder's public contract, so
    asserting its shape is asserting behavior, not implementation internals.
    """

    def test_fips_year_filter_extracts_year_from_validation_history(self) -> None:
        """The FIPS year filter extracts the year from the initial validation_history entry."""
        query = build_query_from_filters({"fips-year-filter": [2020, 2021]}, CollectionName.FIPS140)

        year_expr, years = query["$expr"]["$in"]
        assert years == [2020, 2021]
        first_date = year_expr["$convert"]["input"]["$substr"][0]
        assert first_date == {"$arrayElemAt": [f"${_VALIDATION_HISTORY}.date._value", 0]}

    def test_cc_year_filter_extracts_year_from_scalar_date(self) -> None:
        """The CC year filter extracts the year from the scalar not_valid_before date."""
        query = build_query_from_filters({"cc-year-filter": [2019]}, CollectionName.CommonCriteria)

        year_expr, years = query["$expr"]["$in"]
        assert years == [2019]
        assert year_expr["$cond"]["then"] == {"$year": "$not_valid_before"}

    def test_single_year_value_normalised_to_list(self) -> None:
        """A single (non-list) year value is normalised to a one-element list."""
        query = build_query_from_filters({"cc-year-filter": 2022}, CollectionName.CommonCriteria)

        _, years = query["$expr"]["$in"]
        assert years == [2022]

    def test_string_years_coerced_to_int(self) -> None:
        """Year values arriving as strings (e.g. from a Dash dropdown) are coerced to int."""
        query = build_query_from_filters({"cc-year-filter": ["2020", "2021"]}, CollectionName.CommonCriteria)

        _, years = query["$expr"]["$in"]
        assert years == [2020, 2021]

    def test_empty_year_selection_produces_no_query(self) -> None:
        """An empty selection contributes no query fragment."""
        query = build_query_from_filters({"cc-year-filter": []}, CollectionName.CommonCriteria)

        assert query == {}


class TestResolveDerivedField:
    """Tests for collection-specific derived-field resolution."""

    def test_year_from_resolves_to_collection_specific_definition(self) -> None:
        """year_from resolves to different sources for CC and FIPS."""
        cc_def = resolve_derived_field("year_from", CollectionName.CommonCriteria)
        fips_def = resolve_derived_field("year_from", CollectionName.FIPS140)

        assert cc_def is not None
        assert fips_def is not None
        assert cc_def.source == "not_valid_before"
        assert fips_def.source == _VALIDATION_HISTORY
        assert cc_def.expression != fips_def.expression

    def test_collection_agnostic_field_shared_across_collections(self) -> None:
        """cve_count has a single collection-agnostic definition (None key)."""
        cc_def = resolve_derived_field("cve_count", CollectionName.CommonCriteria)
        fips_def = resolve_derived_field("cve_count", CollectionName.FIPS140)

        assert cc_def is not None
        assert fips_def is not None
        assert cc_def.source == fips_def.source == "heuristics.related_cves._value"

    def test_cc_only_field_returns_none_for_fips(self) -> None:
        """validity_days is CC-only and has no FIPS definition."""
        assert resolve_derived_field("validity_days", CollectionName.CommonCriteria) is not None
        assert resolve_derived_field("validity_days", CollectionName.FIPS140) is None

    def test_year_to_returns_none_for_fips(self) -> None:
        """year_to is CC-only (FIPS modules have no expiration date)."""
        assert resolve_derived_field("year_to", CollectionName.CommonCriteria) is not None
        assert resolve_derived_field("year_to", CollectionName.FIPS140) is None

    def test_unknown_field_returns_none(self) -> None:
        """A non-derived field name resolves to None."""
        assert resolve_derived_field("category", CollectionName.CommonCriteria) is None
