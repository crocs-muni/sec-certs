import re
from typing import TYPE_CHECKING, Any

from ..filters.filter import FilterSpec
from ..filters.registry import FilterSpecRegistry, get_all_registries, get_filter_registry
from ..types.common import CollectionType
from ..types.filter import AggregationType, FilterOperator

if TYPE_CHECKING:
    from ..chart.chart import Chart


_DERIVED_FIELDS: frozenset[str] = frozenset({"year_from", "year_to", "count"})


def get_allowed_database_fields() -> frozenset[str]:
    """Build whitelist of allowed database fields from filter registries.

    Automatically discovers all FilterSpecRegistry subclasses and combines
    their database_field values plus derived fields.
    """
    fields: set[str] = set(_DERIVED_FIELDS)
    for registry in get_all_registries():
        for filter_spec in registry.get_all_filters().values():
            fields.add(filter_spec.database_field)
    return frozenset(fields)


ALLOWED_DATABASE_FIELDS = get_allowed_database_fields()

# DoS prevention limits
_MAX_STRING_VALUE_LENGTH = 1000
_MAX_ARRAY_LENGTH = 100


class FieldValidationError(ValueError):
    """Raised when a field name fails validation."""

    pass


class ValueValidationError(ValueError):
    """Raised when a filter value fails validation."""

    pass


def _validate_field_name(field: str) -> str:
    """Validate a field name against the whitelist.

    The whitelist is derived from filter registries and is the authoritative
    source for allowed field names. This prevents NoSQL injection via field names.

    :param field: Field name to validate
    :return: Validated field name
    :raises FieldValidationError: If field name is invalid or not whitelisted
    """
    if not field:
        raise FieldValidationError("Field name cannot be empty")

    if not isinstance(field, str):
        raise FieldValidationError(f"Field name must be a string, got {type(field).__name__}")

    if field not in ALLOWED_DATABASE_FIELDS:
        raise FieldValidationError(f"Field '{field}' is not in the allowed fields whitelist")

    return field


def _sanitize_string_value(value: str) -> str:
    """Sanitize a string value for use in queries.

    :param value: String value to sanitize
    :return: Sanitized string value
    :raises ValueValidationError: If value exceeds limits or contains dangerous patterns
    """
    if len(value) > _MAX_STRING_VALUE_LENGTH:
        raise ValueValidationError(f"String value exceeds maximum length of {_MAX_STRING_VALUE_LENGTH}")

    if value.startswith("$"):
        raise ValueValidationError("String values cannot start with '$' (MongoDB operator prefix)")

    return value


def _sanitize_regex_value(value: str) -> str:
    """Escape special regex characters to prevent ReDoS attacks.

    :param value: Regex pattern from user input
    :return: Escaped regex pattern safe for MongoDB $regex
    """
    return re.escape(value)


def _validate_filter_value(value: Any, data_type: str) -> Any:
    """Validate and sanitize a filter value based on expected data type.

    Allow other primitive types (int, float, bool, datetime) as-is, but
    recursively validate arrays and sanitize strings.

    :param value: Value to validate
    :param data_type: Expected data type from FilterSpec
    :return: Validated value
    :raises ValueValidationError: If value is invalid
    """
    if value is None:
        return None

    if isinstance(value, str):
        return _sanitize_string_value(value)

    if isinstance(value, (list, tuple)):
        if len(value) > _MAX_ARRAY_LENGTH:
            raise ValueValidationError(f"Array value exceeds maximum length of {_MAX_ARRAY_LENGTH}")
        return [_validate_filter_value(v, data_type) for v in value]

    if isinstance(value, dict):
        raise ValueValidationError("Dictionary values are not allowed in filters (potential operator injection)")

    return value


class QueryBuilder:
    """Builds MongoDB queries from filter values.

    This class uses the Builder pattern to construct MongoDB queries incrementally.
    Each filter added creates a query fragment that's combined into the final query.
    """

    def __init__(self, collection_type: CollectionType, filter_registry: FilterSpecRegistry):
        """Initialize query builder.

        :param collection_type: Dataset type ('cc' or 'fips')
        :param filter_registry: Registry to look up filter specifications
        """
        self.collection_type = collection_type
        self.filter_registry = filter_registry
        self._query_fragments: list[dict[str, Any]] = []
        self._errors: list[str] = []

    def add_filter(self, filter_id: str, value: Any) -> "QueryBuilder":
        """Add a filter to the query.

        :param filter_id: Filter identifier (must match FilterRegistry)
        :param value: Filter value from UI component
        :return: Self for method chaining
        """
        filter_spec = self.filter_registry.get_filter(filter_id)
        if filter_spec is None:
            self._errors.append(f"Unknown filter ID: {filter_id}")
            return self

        query_fragment = self._build_query_fragment(filter_spec, value)
        if query_fragment:
            self._query_fragments.append(query_fragment)

        return self

    def add_filters(self, filters: dict[str, Any]) -> "QueryBuilder":
        """Add multiple filters at once.

        :param filters: Dictionary mapping filter IDs to their values
        :return: Self for method chaining
        """
        for filter_id, value in filters.items():
            self.add_filter(filter_id, value)
        return self

    def build(self) -> dict[str, Any]:
        """Build the final MongoDB query.

        Combines all query fragments using $and operator when multiple
        fragments exist. Returns empty dict if no filters were added.

        :return: MongoDB query dictionary
        """
        if not self._query_fragments:
            return {}

        if len(self._query_fragments) == 1:
            return self._query_fragments[0]

        return {"$and": self._query_fragments}

    def get_errors(self) -> list[str]:
        """Get list of errors encountered during query building.

        :return: List of error messages
        """
        return self._errors.copy()

    def reset(self) -> "QueryBuilder":
        """Reset the builder to empty state.

        :return: Self for method chaining
        """
        self._query_fragments.clear()
        self._errors.clear()
        return self

    @staticmethod
    def _build_query_fragment(filter_spec: FilterSpec, value: Any) -> dict[str, Any] | None:
        """Build MongoDB query fragment from filter spec and value.

        Only builds a fragment if the value is meaningful (not None, empty string,
        empty list, or special "__all__" value). This ensures only "active" filters
        (where user has made a selection) contribute to the query.

        All field names are validated against the whitelist and all values are
        sanitized to prevent NoSQL injection attacks.

        :param filter_spec: Filter specification with configuration
        :param value: Filter value to apply
        :return: MongoDB query fragment or None if value is empty/invalid
        :raises FieldValidationError: If database_field is not whitelisted
        :raises ValueValidationError: If value contains dangerous patterns
        """
        if value is None:
            return None
        if isinstance(value, str) and (not value.strip() or value == "__all__"):
            return None
        if isinstance(value, (list, tuple)) and not value:
            return None

        _validate_field_name(filter_spec.database_field)

        validated_value = _validate_filter_value(value, filter_spec.data_type)

        transformed_value = filter_spec.transform(validated_value) if filter_spec.transform else validated_value

        if filter_spec.operator == FilterOperator.EQ:
            return {filter_spec.database_field: transformed_value}
        elif filter_spec.operator == FilterOperator.REGEX:
            # Escape regex metacharacters to prevent ReDoS
            safe_regex = _sanitize_regex_value(str(transformed_value))
            return {
                filter_spec.database_field: {
                    FilterOperator.REGEX.value: safe_regex,
                    "$options": "i",
                }
            }
        elif filter_spec.operator == FilterOperator.YEAR_IN:
            if isinstance(transformed_value, (list, tuple)):
                years = [int(y) for y in transformed_value]
            else:
                years = [int(transformed_value)]
            return {
                "$expr": {
                    "$in": [
                        {"$toInt": {"$substr": [f"${filter_spec.database_field}._value", 0, 4]}},
                        years,
                    ]
                }
            }
        elif filter_spec.operator in (FilterOperator.IN, FilterOperator.NIN):
            if isinstance(transformed_value, (list, tuple)):
                array_value = list(transformed_value)
            else:
                array_value = [transformed_value]
            return {filter_spec.database_field: {filter_spec.operator.value: array_value}}
        elif filter_spec.operator == FilterOperator.EXISTS:
            bool_value = bool(transformed_value) if not isinstance(transformed_value, bool) else transformed_value
            return {filter_spec.database_field: {filter_spec.operator.value: bool_value}}
        else:
            return {filter_spec.database_field: {filter_spec.operator.value: transformed_value}}


def build_query_from_filters(filter_values: dict[str, Any], collection_type: CollectionType) -> dict[str, Any]:
    """Convenience function to build query from filter values.

    :param filter_values: Dictionary mapping filter IDs to their values
    :param collection_type: Dataset type ('cc' or 'fips'), defaults to 'cc'
    :return: MongoDB query dictionary
    """
    filter_registry = get_filter_registry(collection_type)()
    builder = QueryBuilder(collection_type=collection_type, filter_registry=filter_registry)
    builder.add_filters(filter_values)
    return builder.build()


def build_chart_pipeline(
    chart: "Chart",
    filter_values: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Build complete MongoDB aggregation pipeline for a chart.

    This function creates a pipeline with:
    1. $match stage for filtering (from filter_values)
    2. $group stage for aggregation (from chart.x_axis and chart.y_axis)
    3. $sort stage for ordering results

    All field names are validated against the whitelist to prevent NoSQL injection.

    :param chart: Chart configuration with axis and aggregation settings
    :param filter_values: Optional dictionary mapping filter IDs to values
    :return: MongoDB aggregation pipeline as list of stage dictionaries
    :raises FieldValidationError: If any axis field is not whitelisted

    Example output::

        [
            {"$match": {"category": {"$in": ["Operating Systems"]}}},
            {"$group": {"_id": "$year_from", "count": {"$sum": 1}}},
            {"$sort": {"_id": 1}}
        ]
    """
    _validate_field_name(chart.x_axis.field)
    if chart.y_axis:
        aggregation_placeholders = {agg.value for agg in AggregationType}
        if chart.y_axis.field not in aggregation_placeholders:
            _validate_field_name(chart.y_axis.field)
    if chart.color_axis:
        _validate_field_name(chart.color_axis.field)

    pipeline: list[dict[str, Any]] = []

    if filter_values:
        match_query = build_query_from_filters(filter_values, chart.collection_type)
        if match_query:
            pipeline.append({"$match": match_query})

    group_stage = _build_group_stage(chart)
    if group_stage:
        pipeline.append({"$group": group_stage})

    pipeline.append({"$sort": {"_id": 1}})

    project_stage = _build_project_stage(chart)
    if project_stage:
        pipeline.append({"$project": project_stage})

    return pipeline


# 2. Native MongoDB ISODate objects
DERIVED_FIELD_EXPRESSIONS: dict[str, dict[str, Any]] = {
    "year_from": {
        "source": "not_valid_before",
        "expression": {
            "$cond": {
                "if": {"$eq": [{"$type": "$not_valid_before"}, "date"]},
                "then": {"$year": "$not_valid_before"},
                "else": {"$toInt": {"$substr": ["$not_valid_before._value", 0, 4]}},
            }
        },
    },
    "year_to": {
        "source": "not_valid_after",
        # Use $year for ISODate, fallback to $substr for serialized format (year at positions 0-3)
        "expression": {
            "$cond": {
                "if": {"$eq": [{"$type": "$not_valid_after"}, "date"]},
                "then": {"$year": "$not_valid_after"},
                "else": {"$toInt": {"$substr": ["$not_valid_after._value", 0, 4]}},
            }
        },
    },
}


def _get_field_expression(field: str) -> str | dict[str, Any]:
    """Get the MongoDB expression for a field.

    For derived fields (like year_from), returns the extraction expression.
    For regular fields, returns the simple field reference.

    Field names are validated against the whitelist to prevent injection.

    :param field: Field name (must be in ALLOWED_DATABASE_FIELDS)
    :return: MongoDB field reference or expression
    :raises FieldValidationError: If field is not whitelisted
    """
    _validate_field_name(field)

    if field in DERIVED_FIELD_EXPRESSIONS:
        return DERIVED_FIELD_EXPRESSIONS[field]["expression"]
    return f"${field}"


def _build_group_stage(chart: "Chart") -> dict[str, Any]:
    """Build the $group stage for aggregation.

    Handles both single-level grouping (just x_axis) and two-level grouping
    (x_axis + color_axis for stacked/grouped bar charts).

    :param chart: Chart configuration
    :return: $group stage dictionary
    """
    x_field = chart.x_axis.field
    x_expr = _get_field_expression(x_field)

    if chart.color_axis:
        color_field = chart.color_axis.field
        color_expr = _get_field_expression(color_field)
        group_id = {"x": x_expr, "color": color_expr}
    else:
        group_id = x_expr

    if chart.y_axis and chart.y_axis.aggregation:
        agg_type = chart.y_axis.aggregation
        y_field = chart.y_axis.field

        if agg_type == AggregationType.COUNT:
            return {
                "_id": group_id,
                "value": {"$sum": 1},
            }
        elif agg_type == AggregationType.SUM:
            return {
                "_id": group_id,
                "value": {"$sum": f"${y_field}"},
            }
        elif agg_type == AggregationType.AVG:
            return {
                "_id": group_id,
                "value": {"$avg": f"${y_field}"},
            }
        elif agg_type == AggregationType.MIN:
            return {
                "_id": group_id,
                "value": {"$min": f"${y_field}"},
            }
        elif agg_type == AggregationType.MAX:
            return {
                "_id": group_id,
                "value": {"$max": f"${y_field}"},
            }

    return {
        "_id": group_id,
        "value": {"$sum": 1},
    }


def _build_project_stage(chart: "Chart") -> dict[str, Any]:
    """Build the $project stage to rename fields for clarity.

    Handles both single-level grouping (just x_axis) and two-level grouping
    (x_axis + color_axis for stacked/grouped bar charts).

    Note: For nested fields like "heuristics.eal", we use a flattened name
    (e.g., "heuristics_eal") to avoid MongoDB creating nested documents.

    :param chart: Chart configuration
    :return: $project stage dictionary
    """
    x_field = chart.x_axis.field
    x_field_flat = x_field.replace(".", "_")
    y_label = chart.y_axis.label if chart.y_axis else "count"

    if chart.color_axis:
        color_field = chart.color_axis.field
        color_field_flat = color_field.replace(".", "_")
        return {
            "_id": 0,
            x_field_flat: "$_id.x",
            color_field_flat: "$_id.color",
            y_label: "$value",
        }
    else:
        return {
            "_id": 0,
            x_field_flat: "$_id",
            y_label: "$value",
        }
