from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

import pytest

from sec_certs_page.dashboard.chart.chart import AxisConfig, Chart
from sec_certs_page.dashboard.filters.filter import FilterSpec
from sec_certs_page.dashboard.types.chart import AvailableChartTypes
from sec_certs_page.dashboard.types.common import CollectionName
from sec_certs_page.dashboard.types.filter import (
    AggregationType,
    DashFilterComponentParams,
    FilterComponentType,
    FilterOperator,
)


class TestAxisConfigSerialization:
    """Tests for AxisConfig serialization/deserialization (public API)."""

    def test_to_dict_with_all_fields_returns_complete_dict(self) -> None:
        """to_dict includes all fields when aggregation is set."""
        axis = AxisConfig(
            field="year_from",
            label="Year",
            aggregation=AggregationType.SUM,
        )

        result = axis.to_dict()

        assert result == {
            "field": "year_from",
            "label": "Year",
            "aggregation": AggregationType.SUM,
        }

    def test_from_dict_with_aggregation_restores_all_fields(self) -> None:
        """from_dict correctly restores AxisConfig with aggregation."""
        data: dict[str, Any] = {
            "field": "scheme",
            "label": "Certification Scheme",
            "aggregation": AggregationType.COUNT,
        }

        axis = AxisConfig.from_dict(data)

        assert axis.field == "scheme"
        assert axis.label == "Certification Scheme"
        assert axis.aggregation == AggregationType.COUNT

    def test_from_dict_without_aggregation_sets_none(self) -> None:
        """from_dict sets aggregation to None when not provided."""
        data = {"field": "name", "label": "Name"}

        axis = AxisConfig.from_dict(data)

        assert axis.aggregation is None

    def test_roundtrip_preserves_all_fields(self) -> None:
        """Serialization roundtrip preserves all field values."""
        original = AxisConfig(
            field="heuristics.eal",
            label="EAL Level",
            aggregation=AggregationType.AVG,
        )

        serialized = original.to_dict()
        restored = AxisConfig.from_dict(serialized)

        assert restored.field == original.field
        assert restored.label == original.label
        assert restored.aggregation == original.aggregation

    def test_from_dict_with_nested_field_path_succeeds(self) -> None:
        """from_dict handles dotted field paths for nested documents."""
        data: dict[str, Any] = {"field": "heuristics.eal.value", "label": "EAL Value"}

        axis = AxisConfig.from_dict(data)

        assert axis.field == "heuristics.eal.value"


class TestChartSerialization:
    """Tests for Chart serialization/deserialization (public API)."""

    def test_to_dict_serializes_required_fields(self) -> None:
        """to_dict includes all required fields with correct values."""
        chart = Chart(
            chart_id=uuid4(),
            name="test-chart",
            title="Test Chart",
            chart_type=AvailableChartTypes.BAR,
            collection_type=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
            y_axis=AxisConfig(field="count", label="Count", aggregation=AggregationType.COUNT),
        )

        result = chart.to_dict()

        assert result["name"] == "test-chart"
        assert result["title"] == "Test Chart"
        assert result["chart_type"] == "bar"
        assert result["collection_type"] == "cc"
        assert result["x_axis"]["field"] == "category"
        assert result["y_axis"]["field"] == "count"

    def test_from_dict_with_minimal_fields_succeeds(self) -> None:
        """from_dict creates Chart with only required fields."""
        data: dict[str, Any] = {
            "chart_id": str(uuid4()),
            "name": "from-dict-chart",
            "chart_type": "line",
            "collection_type": "fips",
            "x_axis": {"field": "web_data.level", "label": "Security Level"},
        }

        chart = Chart.from_dict(data)

        assert chart.name == "from-dict-chart"
        assert chart.chart_type == AvailableChartTypes.LINE
        assert chart.collection_type == CollectionName.FIPS140
        assert chart.x_axis.field == "web_data.level"
        assert chart.y_axis is None

    def test_from_dict_with_all_fields_restores_complete_chart(self) -> None:
        """from_dict correctly restores Chart with all optional fields."""
        chart_id = str(uuid4())
        data: dict[str, Any] = {
            "chart_id": chart_id,
            "name": "complete-chart",
            "title": "Complete Chart",
            "order": 5,
            "chart_type": "stacked_bar",
            "collection_type": "cc",
            "x_axis": {"field": "year_from", "label": "Year"},
            "y_axis": {"field": "count", "label": "Count", "aggregation": AggregationType.COUNT},
            "color_axis": {"field": "scheme", "label": "Scheme"},
            "filter_values": {"cc-category-filter": ["ICs"]},
            "query_pipeline": [{"$match": {}}],
            "color_scheme": "viridis",
            "show_legend": False,
            "show_grid": False,
            "created_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-06-20T14:45:00Z",
        }

        chart = Chart.from_dict(data)

        assert chart.chart_id == UUID(chart_id)
        assert chart.title == "Complete Chart"
        assert chart.order == 5
        assert chart.chart_type == AvailableChartTypes.STACKED_BAR
        assert chart.color_axis is not None
        assert chart.color_axis.field == "scheme"
        assert chart.filter_values == {"cc-category-filter": ["ICs"]}
        assert chart.show_legend is False
        assert chart.show_grid is False
        assert chart.created_at is not None
        assert chart.updated_at is not None

    def test_from_dict_missing_required_fields_raises_value_error(self) -> None:
        """from_dict raises ValueError when required fields are missing."""
        incomplete_data: dict[str, Any] = {
            "chart_id": str(uuid4()),
            "name": "incomplete",
        }

        with pytest.raises(ValueError, match="Missing required fields"):
            Chart.from_dict(incomplete_data)

    def test_roundtrip_preserves_all_fields(self) -> None:
        """Serialization roundtrip preserves all chart data."""
        original = Chart(
            chart_id=uuid4(),
            name="test-chart",
            title="Test Chart",
            chart_type=AvailableChartTypes.BAR,
            collection_type=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
            y_axis=AxisConfig(field="count", label="Count", aggregation=AggregationType.COUNT),
        )
        original.set_query_pipeline([{"$match": {"status": "active"}}])

        serialized = original.to_dict()
        restored = Chart.from_dict(serialized)

        assert restored.chart_id == original.chart_id
        assert restored.name == original.name
        assert restored.chart_type == original.chart_type
        assert restored.collection_type == original.collection_type
        assert restored.x_axis.field == original.x_axis.field
        assert restored.query_pipeline == original.query_pipeline


class TestChartFromDictEdgeCases:
    """Tests for Chart.from_dict edge cases and error handling."""

    def test_from_dict_with_uuid_object_succeeds(self) -> None:
        """from_dict accepts UUID object in addition to string."""
        chart_id = uuid4()
        data: dict[str, Any] = {
            "chart_id": chart_id,
            "name": "uuid-object-chart",
            "chart_type": "bar",
            "collection_type": "cc",
            "x_axis": {"field": "category", "label": "Category"},
        }

        chart = Chart.from_dict(data)

        assert chart.chart_id == chart_id

    def test_from_dict_with_enum_objects_succeeds(self) -> None:
        """from_dict accepts enum objects in addition to strings."""
        data: dict[str, Any] = {
            "chart_id": str(uuid4()),
            "name": "enum-object-chart",
            "chart_type": AvailableChartTypes.LINE,
            "collection_type": CollectionName.FIPS140,
            "x_axis": {"field": "level", "label": "Level"},
        }

        chart = Chart.from_dict(data)

        assert chart.chart_type == AvailableChartTypes.LINE
        assert chart.collection_type == CollectionName.FIPS140

    def test_from_dict_invalid_chart_type_raises_value_error(self) -> None:
        """from_dict raises ValueError for unrecognized chart type."""
        data: dict[str, Any] = {
            "chart_id": str(uuid4()),
            "name": "invalid-type-chart",
            "chart_type": "invalid_type",
            "collection_type": "cc",
            "x_axis": {"field": "category", "label": "Category"},
        }

        with pytest.raises(ValueError):
            Chart.from_dict(data)

    def test_from_dict_invalid_collection_type_raises_value_error(self) -> None:
        """from_dict raises ValueError for unrecognized collection type."""
        data: dict[str, Any] = {
            "chart_id": str(uuid4()),
            "name": "invalid-collection-chart",
            "chart_type": "bar",
            "collection_type": "invalid_collection",
            "x_axis": {"field": "category", "label": "Category"},
        }

        with pytest.raises(ValueError):
            Chart.from_dict(data)


class TestChartDatetimeSerialization:
    """Tests for Chart datetime serialization edge cases."""

    def test_to_dict_naive_datetime_adds_z_suffix(self) -> None:
        """to_dict normalizes naive datetime to UTC with Z suffix."""
        chart = Chart(
            chart_id=uuid4(),
            name="naive-datetime-chart",
            chart_type=AvailableChartTypes.BAR,
            collection_type=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
            created_at=datetime(2024, 6, 20, 14, 45, 0),
        )

        serialized = chart.to_dict()

        assert serialized["created_at"].endswith("Z")

    def test_to_dict_utc_datetime_normalizes_to_z_suffix(self) -> None:
        """to_dict converts +00:00 timezone to Z suffix."""
        chart = Chart(
            chart_id=uuid4(),
            name="utc-datetime-chart",
            chart_type=AvailableChartTypes.BAR,
            collection_type=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
            created_at=datetime(2024, 6, 20, 14, 45, 0, tzinfo=timezone.utc),
        )

        serialized = chart.to_dict()

        assert serialized["created_at"] == "2024-06-20T14:45:00Z"

    def test_from_dict_z_suffix_datetime_parses_correctly(self) -> None:
        """from_dict parses Z suffix datetime strings."""
        data: dict[str, Any] = {
            "chart_id": str(uuid4()),
            "name": "z-suffix-chart",
            "chart_type": "bar",
            "collection_type": "cc",
            "x_axis": {"field": "category", "label": "Category"},
            "created_at": "2024-06-20T14:45:00Z",
        }

        chart = Chart.from_dict(data)

        assert chart.created_at is not None
        assert chart.created_at.tzinfo is not None

    def test_from_dict_plus_zero_timezone_parses_correctly(self) -> None:
        """from_dict parses +00:00 timezone format."""
        data: dict[str, Any] = {
            "chart_id": str(uuid4()),
            "name": "plus-zero-chart",
            "chart_type": "bar",
            "collection_type": "cc",
            "x_axis": {"field": "category", "label": "Category"},
            "created_at": "2024-06-20T14:45:00+00:00",
        }

        chart = Chart.from_dict(data)

        assert chart.created_at is not None
        assert chart.created_at.year == 2024

    def test_roundtrip_preserves_created_at_timestamp(self) -> None:
        """Serialization roundtrip preserves created_at timestamp."""
        created = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        chart = Chart(
            chart_id=uuid4(),
            name="timestamp-chart",
            chart_type=AvailableChartTypes.BAR,
            collection_type=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
            created_at=created,
        )

        serialized = chart.to_dict()
        restored = Chart.from_dict(serialized)

        assert restored.created_at == created


class TestChartQueryPipeline:
    """Tests for Chart query pipeline management."""

    def test_set_query_pipeline_stores_pipeline(self) -> None:
        """set_query_pipeline stores the provided pipeline."""
        chart = Chart(
            chart_id=uuid4(),
            name="test-chart",
            chart_type=AvailableChartTypes.BAR,
            collection_type=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
        )
        pipeline = [
            {"$match": {"category": "ICs"}},
            {"$group": {"_id": "$category", "count": {"$sum": 1}}},
        ]

        chart.set_query_pipeline(pipeline)

        assert chart.query_pipeline == pipeline

    def test_set_query_pipeline_updates_timestamp(self) -> None:
        """set_query_pipeline sets updated_at timestamp."""
        chart = Chart(
            chart_id=uuid4(),
            name="test-chart",
            chart_type=AvailableChartTypes.BAR,
            collection_type=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
        )
        assert chart.updated_at is None

        chart.set_query_pipeline([{"$match": {}}])

        assert chart.updated_at is not None
        assert isinstance(chart.updated_at, datetime)

    def test_get_query_pipeline_returns_stored_pipeline(self) -> None:
        """get_query_pipeline returns previously set pipeline."""
        chart = Chart(
            chart_id=uuid4(),
            name="test-chart",
            chart_type=AvailableChartTypes.BAR,
            collection_type=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
        )
        pipeline = [{"$match": {}}]
        chart.set_query_pipeline(pipeline)

        result = chart.get_query_pipeline()

        assert result == pipeline


class TestChartFilterManagement:
    """Tests for chart filter management methods."""

    @pytest.fixture
    def sample_filter(self) -> FilterSpec:
        """Create a sample filter for testing."""
        return FilterSpec(
            id="cc-category-filter",
            database_field="category",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=DashFilterComponentParams(
                label="Category",
                component_type=FilterComponentType.DROPDOWN,
            ),
            active=True,
        )

    def test_add_filter_stores_filter_by_id(self, sample_filter: FilterSpec) -> None:
        """add_filter stores filter accessible by its ID."""
        chart = Chart(
            chart_id=uuid4(),
            name="test-chart",
            chart_type=AvailableChartTypes.BAR,
            collection_type=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
        )

        chart.add_filter(sample_filter)

        assert "cc-category-filter" in chart.filters
        assert chart.filters["cc-category-filter"] == sample_filter

    def test_add_filter_updates_timestamp(self, sample_filter: FilterSpec) -> None:
        """add_filter sets updated_at timestamp."""
        chart = Chart(
            chart_id=uuid4(),
            name="test-chart",
            chart_type=AvailableChartTypes.BAR,
            collection_type=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
        )

        chart.add_filter(sample_filter)

        assert chart.updated_at is not None

    def test_add_filter_with_existing_id_replaces_filter(self, sample_filter: FilterSpec) -> None:
        """add_filter with existing ID replaces the previous filter."""
        chart = Chart(
            chart_id=uuid4(),
            name="test-chart",
            chart_type=AvailableChartTypes.BAR,
            collection_type=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
        )
        chart.add_filter(sample_filter)
        new_filter = FilterSpec(
            id="cc-category-filter",
            database_field="category",
            operator=FilterOperator.EQ,
            data_type="str",
            component_params=DashFilterComponentParams(
                label="Updated Category",
                component_type=FilterComponentType.DROPDOWN,
            ),
            active=False,
        )

        chart.add_filter(new_filter)

        assert len(chart.filters) == 1
        assert chart.filters["cc-category-filter"].operator == FilterOperator.EQ
        assert chart.filters["cc-category-filter"].active is False

    def test_remove_filter_deletes_filter(self, sample_filter: FilterSpec) -> None:
        """remove_filter removes filter from chart."""
        chart = Chart(
            chart_id=uuid4(),
            name="test-chart",
            chart_type=AvailableChartTypes.BAR,
            collection_type=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
        )
        chart.add_filter(sample_filter)

        chart.remove_filter("cc-category-filter")

        assert "cc-category-filter" not in chart.filters

    def test_remove_filter_updates_timestamp(self, sample_filter: FilterSpec) -> None:
        """remove_filter sets updated_at timestamp."""
        chart = Chart(
            chart_id=uuid4(),
            name="test-chart",
            chart_type=AvailableChartTypes.BAR,
            collection_type=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
        )
        chart.add_filter(sample_filter)

        chart.remove_filter("cc-category-filter")

        assert chart.updated_at is not None

    def test_remove_filter_nonexistent_raises_key_error(self) -> None:
        """remove_filter raises KeyError for non-existent filter ID."""
        chart = Chart(
            chart_id=uuid4(),
            name="test-chart",
            chart_type=AvailableChartTypes.BAR,
            collection_type=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
        )

        with pytest.raises(KeyError):
            chart.remove_filter("nonexistent-filter")

    def test_get_active_filters_returns_only_active(self) -> None:
        """get_active_filters excludes inactive filters."""
        chart = Chart(
            chart_id=uuid4(),
            name="multi-filter-chart",
            chart_type=AvailableChartTypes.BAR,
            collection_type=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
        )
        active_filter = FilterSpec(
            id="active-filter",
            database_field="category",
            operator=FilterOperator.IN,
            data_type="str",
            component_params=DashFilterComponentParams(
                label="Active",
                component_type=FilterComponentType.DROPDOWN,
            ),
            active=True,
        )
        inactive_filter = FilterSpec(
            id="inactive-filter",
            database_field="scheme",
            operator=FilterOperator.EQ,
            data_type="str",
            component_params=DashFilterComponentParams(
                label="Inactive",
                component_type=FilterComponentType.DROPDOWN,
            ),
            active=False,
        )
        chart.add_filter(active_filter)
        chart.add_filter(inactive_filter)

        active_filters = chart.get_active_filters()

        assert len(active_filters) == 1
        assert "active-filter" in active_filters
        assert "inactive-filter" not in active_filters

    def test_get_active_filters_no_filters_returns_empty_dict(self) -> None:
        """get_active_filters returns empty dict when no filters exist."""
        chart = Chart(
            chart_id=uuid4(),
            name="no-filters-chart",
            chart_type=AvailableChartTypes.BAR,
            collection_type=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
        )

        active_filters = chart.get_active_filters()

        assert active_filters == {}

    def test_get_active_filters_all_inactive_returns_empty_dict(self) -> None:
        """get_active_filters returns empty dict when all filters inactive."""
        chart = Chart(
            chart_id=uuid4(),
            name="all-inactive-chart",
            chart_type=AvailableChartTypes.BAR,
            collection_type=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
        )
        filter1 = FilterSpec(
            id="filter1",
            database_field="f1",
            operator=FilterOperator.EQ,
            data_type="str",
            component_params=DashFilterComponentParams(label="F1", component_type=FilterComponentType.DROPDOWN),
            active=False,
        )
        filter2 = FilterSpec(
            id="filter2",
            database_field="f2",
            operator=FilterOperator.EQ,
            data_type="str",
            component_params=DashFilterComponentParams(label="F2", component_type=FilterComponentType.DROPDOWN),
            active=False,
        )
        chart.add_filter(filter1)
        chart.add_filter(filter2)

        active = chart.get_active_filters()

        assert active == {}


class TestChartWithColorAxis:
    """Tests for stacked bar chart with color axis."""

    def test_stacked_bar_with_color_axis_stores_axis(self) -> None:
        """Stacked bar chart stores color axis configuration."""
        chart = Chart(
            chart_id=uuid4(),
            name="stacked-test",
            chart_type=AvailableChartTypes.STACKED_BAR,
            collection_type=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="year_from", label="Year"),
            y_axis=AxisConfig(field="count", label="Count", aggregation=AggregationType.COUNT),
            color_axis=AxisConfig(field="scheme", label="Scheme"),
        )

        assert chart.color_axis is not None
        assert chart.color_axis.field == "scheme"
