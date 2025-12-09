"""Aggregation type utilities - kept separate to avoid circular imports with pages."""

from .filter import AggregationType

DATA_TYPE_AGGREGATIONS: dict[str, list[AggregationType]] = {
    # Numeric types support all aggregations
    "int": [AggregationType.COUNT, AggregationType.SUM, AggregationType.AVG, AggregationType.MIN, AggregationType.MAX],
    "float": [
        AggregationType.COUNT,
        AggregationType.SUM,
        AggregationType.AVG,
        AggregationType.MIN,
        AggregationType.MAX,
    ],
    "number": [
        AggregationType.COUNT,
        AggregationType.SUM,
        AggregationType.AVG,
        AggregationType.MIN,
        AggregationType.MAX,
    ],
    "numeric": [
        AggregationType.COUNT,
        AggregationType.SUM,
        AggregationType.AVG,
        AggregationType.MIN,
        AggregationType.MAX,
    ],
    # String types only support COUNT
    "str": [AggregationType.COUNT],
    "string": [AggregationType.COUNT],
    # Date types support COUNT, MIN, MAX
    "date": [AggregationType.COUNT, AggregationType.MIN, AggregationType.MAX],
    "datetime": [AggregationType.COUNT, AggregationType.MIN, AggregationType.MAX],
    # Boolean only supports COUNT
    "bool": [AggregationType.COUNT],
    "boolean": [AggregationType.COUNT],
}

DEFAULT_AGGREGATIONS = [AggregationType.COUNT]


def get_aggregations_for_type(data_type: str) -> list[dict[str, str]]:
    """
    Get available aggregation options based on data type.

    :param data_type: The data type string (e.g., "int", "str", "date")
    :return: List of dicts with 'label' and 'value' for dropdown options
    """
    aggregations = DATA_TYPE_AGGREGATIONS.get(data_type.lower(), DEFAULT_AGGREGATIONS)
    return [{"label": agg.value.upper(), "value": agg.value} for agg in aggregations]
