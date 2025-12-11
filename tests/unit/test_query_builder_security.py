"""Tests for NoSQL injection protection in QueryBuilder.

These are pure unit tests that don't require MongoDB or any fixtures.
"""

import pytest

from sec_certs_page.dashboard.filters.query_builder import (
    ALLOWED_DATABASE_FIELDS,
    FieldValidationError,
    ValueValidationError,
    _sanitize_string_value,
    _validate_field_name,
    _validate_filter_value,
    get_allowed_database_fields,
)
from sec_certs_page.dashboard.filters.registry import get_all_registries


class TestFieldValidation:
    """Tests for field name validation against injection attacks."""

    def test_valid_field_passes(self):
        """Whitelisted fields should pass validation."""
        for field in ["category", "scheme", "status", "heuristics.eal"]:
            assert _validate_field_name(field) == field

    def test_invalid_field_rejected(self):
        """Non-whitelisted fields should be rejected."""
        with pytest.raises(FieldValidationError, match="not in the allowed fields whitelist"):
            _validate_field_name("malicious_field")

    def test_dollar_prefix_rejected(self):
        """Fields starting with $ should be rejected (MongoDB operator prefix)."""
        with pytest.raises(FieldValidationError):
            _validate_field_name("$gt")

    def test_empty_field_rejected(self):
        """Empty field names should be rejected."""
        with pytest.raises(FieldValidationError, match="cannot be empty"):
            _validate_field_name("")

    def test_non_string_field_rejected(self):
        """Non-string field names should be rejected."""
        with pytest.raises(FieldValidationError, match="must be a string"):
            _validate_field_name(123)  # type: ignore

    def test_injection_via_field_name_blocked(self):
        """Attempted operator injection via field names should be blocked."""
        malicious_fields = [
            "$where",
            "$gt",
            "$lookup",
            "field}}, {$lookup: {from: 'users'}",
            "__proto__",
            "constructor",
        ]
        for field in malicious_fields:
            with pytest.raises(FieldValidationError):
                _validate_field_name(field)


class TestValueValidation:
    """Tests for filter value validation and sanitization."""

    def test_string_value_sanitized(self):
        """Normal string values should pass."""
        assert _sanitize_string_value("normal value") == "normal value"

    def test_dollar_prefix_string_rejected(self):
        """String values starting with $ should be rejected."""
        with pytest.raises(ValueValidationError, match="cannot start with"):
            _sanitize_string_value("$gt")

    def test_long_string_rejected(self):
        """Excessively long strings should be rejected (DoS prevention)."""
        long_string = "a" * 2000
        with pytest.raises(ValueValidationError, match="exceeds maximum length"):
            _sanitize_string_value(long_string)

    def test_dict_value_rejected(self):
        """Dictionary values should be rejected (operator injection prevention)."""
        with pytest.raises(ValueValidationError, match="Dictionary values are not allowed"):
            _validate_filter_value({"$gt": 100}, "int")

    def test_nested_operator_injection_blocked(self):
        """Nested operator injection attempts should be blocked."""
        malicious_value = {"$gt": "", "$lt": 1000}
        with pytest.raises(ValueValidationError):
            _validate_filter_value(malicious_value, "str")

    def test_large_array_rejected(self):
        """Excessively large arrays should be rejected (DoS prevention)."""
        large_array = list(range(200))
        with pytest.raises(ValueValidationError, match="exceeds maximum length"):
            _validate_filter_value(large_array, "int")

    def test_valid_array_passes(self):
        """Normal arrays should pass validation."""
        result = _validate_filter_value(["value1", "value2"], "str")
        assert result == ["value1", "value2"]

    def test_none_value_passes(self):
        """None values should pass (they're filtered out later)."""
        assert _validate_filter_value(None, "str") is None

    def test_primitive_types_pass(self):
        """Primitive types (int, float, bool) should pass."""
        assert _validate_filter_value(42, "int") == 42
        assert _validate_filter_value(3.14, "float") == 3.14
        assert _validate_filter_value(True, "bool") is True


class TestRegexSanitization:
    """Tests for regex value sanitization (ReDoS prevention)."""

    def test_simple_alphanumeric_unchanged(self):
        """Simple alphanumeric text should remain unchanged after escaping."""
        # _sanitize_regex_value was removed/inlined, testing _sanitize_string_value instead
        # as it's the primary sanitization mechanism now
        assert _sanitize_string_value("helloworld") == "helloworld"
        assert _sanitize_string_value("test123") == "test123"


class TestAllowedFieldsDerivation:
    """Tests to ensure the whitelist is correctly derived from registries."""

    def test_whitelist_includes_derived_fields(self):
        """Derived fields (year_from, year_to) should be in whitelist."""
        fields = get_allowed_database_fields()
        assert "year_from" in fields
        assert "year_to" in fields

    def test_whitelist_includes_all_registry_fields(self):
        """Whitelist should include all fields from all filter registries."""
        fields = get_allowed_database_fields()

        # Dynamically check all registries
        for registry in get_all_registries():
            for filter_spec in registry.get_all_filters().values():
                assert (
                    filter_spec.database_field in fields
                ), f"Field '{filter_spec.database_field}' from {registry.__name__} missing"

    def test_whitelist_is_frozenset(self):
        """Whitelist should be immutable."""
        fields = get_allowed_database_fields()
        assert isinstance(fields, frozenset)

    def test_constant_matches_function(self):
        """ALLOWED_DATABASE_FIELDS constant should match function output."""
        assert ALLOWED_DATABASE_FIELDS == get_allowed_database_fields()
