from typing import TYPE_CHECKING, Any

from ..filters.filter import FilterSpec
from ..filters.registry import FilterSpecRegistry, get_filter_registry
from ..types.common import CollectionName
from ..types.filter import AggregationType, FilterOperator

if TYPE_CHECKING:
    from ..chart.chart import Chart


class QueryBuilder:
    """Builds MongoDB queries from filter values.

    This class uses the Builder pattern to construct MongoDB queries incrementally.
    Each filter added creates a query fragment that's combined into the final query.
    """

    def __init__(self, dataset_type: CollectionName, filter_registry: FilterSpecRegistry):
        """Initialize query builder.

        :param dataset_type: Dataset type ('cc' or 'fips')
        :param filter_registry: Registry to look up filter specifications
        """
        self.dataset_type = dataset_type
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

        # Combine multiple fragments with $and
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

        :param filter_spec: Filter specification with configuration
        :param value: Filter value to apply
        :return: MongoDB query fragment or None if value is empty/invalid
        """
        # Skip empty/null values - only active filters should be included
        if value is None:
            return None
        if isinstance(value, str) and (not value.strip() or value == "__all__"):
            return None
        if isinstance(value, (list, tuple)) and not value:
            return None

        transformed_value = filter_spec.transform(value) if filter_spec.transform else value

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
            # Special handling for year extraction from serialized date fields
            # Dates are stored as {"_type": "date", "_value": "YYYY-MM-DD"}
            # Extract year from the _value string (first 4 characters) and match
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
            # $in and $nin require an array value
            if isinstance(transformed_value, (list, tuple)):
                array_value = list(transformed_value)
            else:
                array_value = [transformed_value]
            return {filter_spec.database_field: {filter_spec.operator.value: array_value}}
        elif filter_spec.operator == FilterOperator.EXISTS:
            # $exists requires a boolean value
            bool_value = bool(transformed_value) if not isinstance(transformed_value, bool) else transformed_value
            return {filter_spec.database_field: {filter_spec.operator.value: bool_value}}
        else:
            return {filter_spec.database_field: {filter_spec.operator.value: transformed_value}}


def build_query_from_filters(filter_values: dict[str, Any], dataset_type: CollectionName) -> dict[str, Any]:
    """Convenience function to build query from filter values.

    :param filter_values: Dictionary mapping filter IDs to their values
    :param dataset_type: Dataset type ('cc' or 'fips'), defaults to 'cc'
    :return: MongoDB query dictionary
    """
    filter_registry = get_filter_registry(dataset_type)()
    builder = QueryBuilder(dataset_type=dataset_type, filter_registry=filter_registry)
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

    :param chart: Chart configuration with axis and aggregation settings
    :param filter_values: Optional dictionary mapping filter IDs to values
    :return: MongoDB aggregation pipeline as list of stage dictionaries

    Example output::

        [
            {"$match": {"category": {"$in": ["Operating Systems"]}}},
            {"$group": {"_id": "$year_from", "count": {"$sum": 1}}},
            {"$sort": {"_id": 1}}
        ]
    """
    pipeline: list[dict[str, Any]] = []

    # Stage 1: $match (filtering)
    if filter_values:
        match_query = build_query_from_filters(filter_values, chart.collection_type)
        if match_query:
            pipeline.append({"$match": match_query})

    # Stage 2: $group (aggregation based on axes)
    group_stage = _build_group_stage(chart)
    if group_stage:
        pipeline.append({"$group": group_stage})

    # Stage 3: $sort (order by x-axis field)
    pipeline.append({"$sort": {"_id": 1}})

    # Stage 4: $project (rename _id to x-axis field name for clarity)
    project_stage = _build_project_stage(chart)
    if project_stage:
        pipeline.append({"$project": project_stage})

    return pipeline


# Mapping of derived fields to their source fields and extraction expressions
# Handles both:
# 1. Serialized dates stored as {"_type": "date", "_value": "YYYY-MM-DD"}
# 2. Native MongoDB ISODate objects
DERIVED_FIELD_EXPRESSIONS: dict[str, dict[str, Any]] = {
    "year_from": {
        "source": "not_valid_before",
        # Use $year for ISODate, fallback to $substr for serialized format
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

    :param field: Field name
    :return: MongoDB field reference or expression
    """
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

    # Determine the group _id (single field or compound)
    if chart.color_axis:
        # Two-level grouping: group by both x_field and color_field
        color_field = chart.color_axis.field
        color_expr = _get_field_expression(color_field)
        group_id = {"x": x_expr, "color": color_expr}
    else:
        # Single-level grouping: just x_field
        group_id = x_expr

    # Determine the aggregation operation
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

    # Default: COUNT
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
    # Flatten dotted field names for use as column names (avoid nested documents)
    x_field_flat = x_field.replace(".", "_")
    y_label = chart.y_axis.label if chart.y_axis else "count"

    if chart.color_axis:
        # Two-level grouping: extract x and color from compound _id
        color_field = chart.color_axis.field
        color_field_flat = color_field.replace(".", "_")
        return {
            "_id": 0,
            x_field_flat: "$_id.x",
            color_field_flat: "$_id.color",
            y_label: "$value",
        }
    else:
        # Single-level grouping
        return {
            "_id": 0,
            x_field_flat: "$_id",
            y_label: "$value",
        }
