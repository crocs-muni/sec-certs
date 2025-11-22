from typing import Any

from sec_certs_page.dashboard.filters.filter import FilterSpec
from sec_certs_page.dashboard.filters.registry import FilterSpecRegistry, get_filter_registry
from sec_certs_page.dashboard.types.common import CollectionName
from sec_certs_page.dashboard.types.filter import FilterOperator


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

        :param filter_spec: Filter specification with configuration
        :param value: Filter value to apply
        :return: MongoDB query fragment or None if value is invalid
        """
        if value is None or (isinstance(value, (list, tuple)) and not value):
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
