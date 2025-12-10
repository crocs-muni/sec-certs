from typing import TYPE_CHECKING, Any

from ..filters.filter import FilterSpec
from ..filters.registry import FilterSpecRegistry, get_all_registries, get_filter_registry
from ..types.chart import ChartType
from ..types.common import CollectionName
from ..types.filter import AggregationType, DerivedFieldDefinition, FilterOperator

if TYPE_CHECKING:
    from ..chart.config import ChartConfig


_DERIVED_FIELDS: frozenset[str] = frozenset({
    "year_from",
    "year_to",
    "count",
    "validity_days",
    # CVE-related derived fields
    "cve_count",
    "direct_transitive_cve_count",
    "indirect_transitive_cve_count",
    "total_transitive_cve_count",
})


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

    def __init__(self, collection_name: CollectionName, filter_registry: FilterSpecRegistry):
        """Initialize query builder.

        :param collection_name: Dataset type ('cc' or 'fips')
        :param filter_registry: Registry to look up filter specifications
        """
        self.collection_name = collection_name
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
            return {
                filter_spec.database_field: {
                    FilterOperator.REGEX.value: transformed_value,
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


def build_query_from_filters(filter_values: dict[str, Any], collection_name: CollectionName) -> dict[str, Any]:
    """Convenience function to build query from filter values.

    :param filter_values: Dictionary mapping filter IDs to their values
    :param collection_name: Dataset type ('cc' or 'fips')
    :return: MongoDB query dictionary
    """
    filter_registry = get_filter_registry(collection_name)()
    builder = QueryBuilder(collection_name=collection_name, filter_registry=filter_registry)
    builder.add_filters(filter_values)
    return builder.build()


def build_chart_pipeline(
    chart: "ChartConfig",
    filter_values: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Build complete MongoDB aggregation pipeline for a chart.

    This function creates a pipeline with:
    1. $match stage for filtering (from filter_values)
    2. $group stage for aggregation (from chart.x_axis and chart.y_axis)
    3. $sort stage for ordering results

    For BOX and HISTOGRAM charts, aggregation is skipped and raw data is returned
    (with only filtering and projection).

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
        match_query = build_query_from_filters(filter_values, chart.collection_name)
        if match_query:
            pipeline.append({"$match": match_query})

    # Box plots and histograms need raw data, not aggregated summaries
    if chart.chart_type in (ChartType.BOX, ChartType.HISTOGRAM):
        # Add $addFields stage to compute derived fields if needed
        add_fields_stage = _build_add_fields_stage(chart)
        if add_fields_stage:
            pipeline.append({"$addFields": add_fields_stage})

        # Project only the fields we need for the chart
        project_fields = {chart.x_axis.field: 1}
        # For box plots, include y_field if it's a real field (not a placeholder like "count")
        if chart.chart_type == ChartType.BOX and chart.y_axis and chart.y_axis.field:
            # Only project if it's not a placeholder aggregation value
            aggregation_placeholders = {agg.value for agg in AggregationType}
            if chart.y_axis.field not in aggregation_placeholders:
                project_fields[chart.y_axis.field] = 1
        if chart.color_axis and chart.color_axis.field:
            project_fields[chart.color_axis.field] = 1
        pipeline.append({"$project": project_fields})

        # Sort by x-axis for better visualization
        pipeline.append({"$sort": {chart.x_axis.field: 1}})
        return pipeline

    # For other chart types, use aggregation
    group_stage = _build_group_stage(chart)
    if group_stage:
        pipeline.append({"$group": group_stage})

    pipeline.append({"$sort": {"_id": 1}})

    project_stage = _build_project_stage(chart)
    if project_stage:
        pipeline.append({"$project": project_stage})

    return pipeline


DERIVED_FIELD_EXPRESSIONS: dict[str, DerivedFieldDefinition] = {
    "year_from": DerivedFieldDefinition(
        source="not_valid_before",
        label="Certificate Year",
        data_type="int",
        expression={
            "$cond": {
                "if": {"$eq": [{"$type": "$not_valid_before"}, "date"]},
                "then": {"$year": "$not_valid_before"},
                "else": {"$toInt": {"$substr": ["$not_valid_before._value", 0, 4]}},
            }
        },
    ),
    "year_to": DerivedFieldDefinition(
        source="not_valid_after",
        label="Expiration Year",
        data_type="int",
        # Use $year for ISODate, fallback to $substr for serialized format (year at positions 0-3)
        expression={
            "$cond": {
                "if": {"$eq": [{"$type": "$not_valid_after"}, "date"]},
                "then": {"$year": "$not_valid_after"},
                "else": {"$toInt": {"$substr": ["$not_valid_after._value", 0, 4]}},
            }
        },
    ),
    "validity_days": DerivedFieldDefinition(
        source=["not_valid_before", "not_valid_after"],
        label="Validity Duration (days)",
        data_type="int",
        # Calculate difference in milliseconds, convert to days
        expression={
            "$divide": [
                {
                    "$subtract": [
                        {
                            "$cond": {
                                "if": {"$eq": [{"$type": "$not_valid_after"}, "date"]},
                                "then": "$not_valid_after",
                                "else": {"$dateFromString": {"dateString": "$not_valid_after._value"}},
                            }
                        },
                        {
                            "$cond": {
                                "if": {"$eq": [{"$type": "$not_valid_before"}, "date"]},
                                "then": "$not_valid_before",
                                "else": {"$dateFromString": {"dateString": "$not_valid_before._value"}},
                            }
                        },
                    ]
                },
                86400000,  # Milliseconds in a day
            ]
        },
    ),
    # CVE-related derived fields for vulnerability analysis
    "cve_count": DerivedFieldDefinition(
        source="heuristics.related_cves._value",
        label="CVE Count",
        data_type="int",
        expression={"$size": {"$ifNull": ["$heuristics.related_cves._value", []]}},
    ),
    "direct_transitive_cve_count": DerivedFieldDefinition(
        source="heuristics.direct_transitive_cves._value",
        label="Direct Transitive CVE Count",
        data_type="int",
        expression={"$size": {"$ifNull": ["$heuristics.direct_transitive_cves._value", []]}},
    ),
    "indirect_transitive_cve_count": DerivedFieldDefinition(
        source="heuristics.indirect_transitive_cves._value",
        label="Indirect Transitive CVE Count",
        data_type="int",
        expression={"$size": {"$ifNull": ["$heuristics.indirect_transitive_cves._value", []]}},
    ),
    "total_transitive_cve_count": DerivedFieldDefinition(
        source=["heuristics.direct_transitive_cves._value", "heuristics.indirect_transitive_cves._value"],
        label="Total Transitive CVE Count",
        data_type="int",
        expression={
            "$add": [
                {"$size": {"$ifNull": ["$heuristics.direct_transitive_cves._value", []]}},
                {"$size": {"$ifNull": ["$heuristics.indirect_transitive_cves._value", []]}},
            ]
        },
    ),
}


def _build_add_fields_stage(chart: "ChartConfig") -> dict[str, Any] | None:
    """Build $addFields stage for derived fields.

    This is used for box plots and histograms that need raw data with
    computed fields like year_from or validity_days.

    :param chart: Chart configuration
    :return: Dictionary for $addFields stage or None if no derived fields needed
    """
    fields_to_add = {}

    # Check all axes for derived fields
    all_fields = [chart.x_axis.field]
    if chart.y_axis and chart.y_axis.field:
        all_fields.append(chart.y_axis.field)
    if chart.color_axis and chart.color_axis.field:
        all_fields.append(chart.color_axis.field)

    for field in all_fields:
        if field in DERIVED_FIELD_EXPRESSIONS:
            fields_to_add[field] = DERIVED_FIELD_EXPRESSIONS[field].expression

    return fields_to_add if fields_to_add else None


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
        return DERIVED_FIELD_EXPRESSIONS[field].expression
    return f"${field}"


def _get_aggregation_field_expr(field: str) -> str | dict[str, Any]:
    """Get the MongoDB expression for a field to be used in aggregation.

    For derived fields (like cve_count), returns the computation expression.
    For regular fields, returns the simple field reference.

    Unlike _get_field_expression, this doesn't validate against whitelist
    since aggregation fields might be derived fields not in the filter registry.

    :param field: Field name
    :return: MongoDB field reference or expression
    """
    if field in DERIVED_FIELD_EXPRESSIONS:
        return DERIVED_FIELD_EXPRESSIONS[field].expression
    return f"${field}"


def _build_group_stage(chart: "ChartConfig") -> dict[str, Any]:
    """Build the $group stage for aggregation.

    Handles both single-level grouping (just x_axis) and two-level grouping
    (x_axis + color_axis for stacked/grouped bar charts).

    For derived fields like cve_count, uses their expressions for aggregation.

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
            # Use derived field expression if available
            y_expr = _get_aggregation_field_expr(y_field)
            return {
                "_id": group_id,
                "value": {"$sum": y_expr},
            }
        elif agg_type == AggregationType.AVG:
            y_expr = _get_aggregation_field_expr(y_field)
            return {
                "_id": group_id,
                "value": {"$avg": y_expr},
            }
        elif agg_type == AggregationType.MIN:
            y_expr = _get_aggregation_field_expr(y_field)
            return {
                "_id": group_id,
                "value": {"$min": y_expr},
            }
        elif agg_type == AggregationType.MAX:
            y_expr = _get_aggregation_field_expr(y_field)
            return {
                "_id": group_id,
                "value": {"$max": y_expr},
            }

    return {
        "_id": group_id,
        "value": {"$sum": 1},
    }


def _build_project_stage(chart: "ChartConfig") -> dict[str, Any]:
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
