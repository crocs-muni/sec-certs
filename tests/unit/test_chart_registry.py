"""Unit tests for ChartRegistry class.

Tests chart registration, lookup, and iteration through public APIs.
"""

import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

import pytest
from dash.development.base_component import Component

from sec_certs_page.dashboard.chart.base import BaseChart
from sec_certs_page.dashboard.chart.chart import AxisConfig, Chart
from sec_certs_page.dashboard.chart.registry import ChartRegistry
from sec_certs_page.dashboard.types.chart import AvailableChartTypes
from sec_certs_page.dashboard.types.common import CollectionName


class FakeComponent(Component):
    """Fake Dash component for testing without external dependencies."""

    def __init__(self) -> None:
        self._prop_names: list[str] = []
        self._valid_wildcard_attributes: list[str] = []


@dataclass
class FakeChart(BaseChart):
    """Fake chart implementation for testing ChartRegistry.

    Implements all abstract methods from BaseChart without external dependencies.
    """

    graph_id: str = ""
    data_service: Any = field(default=None)
    chart_type: Literal["pie", "bar", "box", "line", "scatter", "histogram"] = "bar"
    config: Chart = field(default=None)  # type: ignore[assignment]

    def __post_init__(self) -> None:
        """Initialize config with default Chart if not provided."""
        if self.config is None:
            self.config = Chart(
                chart_id=uuid.uuid4(),
                name=self.graph_id,
                title="Fake Chart",
                chart_type=AvailableChartTypes.BAR,
                collection_type=CollectionName.CommonCriteria,
                x_axis=AxisConfig(field="test", label="Test"),
            )

    @property
    def title(self) -> str:
        """Return chart title."""
        return self.config.title

    def render(self, filter_values: dict[str, Any] | None = None) -> Component:
        """Return fake component for rendering."""
        return FakeComponent()


class TestChartRegistryRegistration:
    """Tests for ChartRegistry registration operations."""

    @pytest.fixture
    def registry(self) -> ChartRegistry:
        """Create a fresh ChartRegistry for testing."""
        return ChartRegistry(CollectionName.CommonCriteria)

    def test_register_adds_chart_to_predefined_charts(self, registry: ChartRegistry) -> None:
        """register adds chart to predefined charts collection."""
        # Arrange
        chart = FakeChart(graph_id="test-chart")

        # Act
        registry.register(chart)

        # Assert
        assert registry.get_predefined("test-chart") == chart

    def test_register_with_duplicate_id_raises_value_error(self, registry: ChartRegistry) -> None:
        """register raises ValueError when chart ID already exists."""
        # Arrange
        chart1 = FakeChart(graph_id="duplicate-id")
        chart2 = FakeChart(graph_id="duplicate-id")
        registry.register(chart1)

        # Act & Assert
        with pytest.raises(ValueError, match="already registered"):
            registry.register(chart2)

    def test_register_active_adds_chart_to_active_charts(self, registry: ChartRegistry) -> None:
        """register_active adds chart to active charts collection."""
        # Arrange
        chart = FakeChart(graph_id="active-chart")

        # Act
        registry.register_active(chart)

        # Assert
        assert registry.get("active-chart") == chart

    def test_register_active_allows_updating_existing_chart(self, registry: ChartRegistry) -> None:
        """register_active replaces existing chart with same ID."""
        # Arrange
        original_chart = FakeChart(graph_id="chart-id")
        updated_chart = FakeChart(graph_id="chart-id")
        registry.register_active(original_chart)

        # Act
        registry.register_active(updated_chart)

        # Assert
        assert registry.get("chart-id") == updated_chart

    def test_register_with_empty_id_succeeds(self, registry: ChartRegistry) -> None:
        """register accepts chart with empty string ID."""
        # Arrange
        chart = FakeChart(graph_id="")

        # Act
        registry.register(chart)

        # Assert
        assert registry.get_predefined("") == chart


class TestChartRegistryLookup:
    """Tests for ChartRegistry lookup operations."""

    @pytest.fixture
    def registry(self) -> ChartRegistry:
        """Create a ChartRegistry with predefined and active charts."""
        registry = ChartRegistry(CollectionName.CommonCriteria)
        registry.register(FakeChart(graph_id="predefined-chart"))
        registry.register_active(FakeChart(graph_id="active-chart"))
        return registry

    def test_get_returns_active_chart_when_both_exist_with_same_id(self, registry: ChartRegistry) -> None:
        """get returns active chart over predefined when IDs match."""
        # Arrange
        predefined = FakeChart(graph_id="same-id")
        active = FakeChart(graph_id="same-id")
        registry.register(predefined)
        registry.register_active(active)

        # Act
        result = registry.get("same-id")

        # Assert
        assert result == active

    def test_get_returns_predefined_when_no_active_exists(self, registry: ChartRegistry) -> None:
        """get returns predefined chart when no active chart has matching ID."""
        # Arrange - predefined-chart exists from fixture

        # Act
        result = registry.get("predefined-chart")

        # Assert
        assert result is not None
        assert result.id == "predefined-chart"

    def test_get_returns_none_for_nonexistent_id(self, registry: ChartRegistry) -> None:
        """get returns None when no chart matches the ID."""
        # Arrange - registry has charts but not "nonexistent"

        # Act
        result = registry.get("nonexistent")

        # Assert
        assert result is None

    def test_get_predefined_only_searches_predefined_charts(self, registry: ChartRegistry) -> None:
        """get_predefined does not search active charts."""
        # Arrange - active-chart exists only in active collection

        # Act
        result = registry.get_predefined("active-chart")

        # Assert
        assert result is None

    def test_getitem_returns_chart_for_valid_id(self, registry: ChartRegistry) -> None:
        """__getitem__ returns chart when ID exists."""
        # Arrange - predefined-chart exists from fixture

        # Act
        result = registry["predefined-chart"]

        # Assert
        assert result.id == "predefined-chart"

    def test_getitem_raises_key_error_for_nonexistent_id(self, registry: ChartRegistry) -> None:
        """__getitem__ raises KeyError when ID not found."""
        # Arrange - registry does not have "nonexistent"

        # Act & Assert
        with pytest.raises(KeyError, match="not found"):
            _ = registry["nonexistent"]


class TestChartRegistryActiveManagement:
    """Tests for ChartRegistry active chart management."""

    @pytest.fixture
    def registry(self) -> ChartRegistry:
        """Create a ChartRegistry for testing."""
        return ChartRegistry(CollectionName.CommonCriteria)

    def test_unregister_active_removes_chart(self, registry: ChartRegistry) -> None:
        """unregister_active removes chart from active collection."""
        # Arrange
        chart = FakeChart(graph_id="to-remove")
        registry.register_active(chart)

        # Act
        registry.unregister_active("to-remove")

        # Assert
        assert registry.get("to-remove") is None

    def test_unregister_active_with_nonexistent_id_does_not_raise(self, registry: ChartRegistry) -> None:
        """unregister_active silently ignores non-existent chart ID."""
        # Arrange - registry is empty

        # Act & Assert (no exception)
        registry.unregister_active("nonexistent")

    def test_clear_active_removes_all_active_but_keeps_predefined(self, registry: ChartRegistry) -> None:
        """clear_active removes active charts but preserves predefined."""
        # Arrange
        registry.register(FakeChart(graph_id="predefined"))
        registry.register_active(FakeChart(graph_id="active1"))
        registry.register_active(FakeChart(graph_id="active2"))

        # Act
        registry.clear_active()

        # Assert
        assert registry.get("predefined") is not None
        assert registry.get("active1") is None
        assert registry.get("active2") is None

    def test_clear_active_on_empty_registry_does_not_raise(self, registry: ChartRegistry) -> None:
        """clear_active on registry with no active charts does not raise."""
        # Arrange - registry has no active charts

        # Act & Assert (no exception)
        registry.clear_active()


class TestChartRegistryIteration:
    """Tests for ChartRegistry iteration and length."""

    @pytest.fixture
    def registry(self) -> ChartRegistry:
        """Create a ChartRegistry with charts."""
        registry = ChartRegistry(CollectionName.CommonCriteria)
        registry.register(FakeChart(graph_id="chart1"))
        registry.register(FakeChart(graph_id="chart2"))
        registry.register_active(FakeChart(graph_id="active1"))
        return registry

    def test_iter_yields_only_predefined_charts(self, registry: ChartRegistry) -> None:
        """__iter__ yields predefined charts, not active charts."""
        # Arrange - registry has 2 predefined and 1 active from fixture

        # Act
        chart_ids = [chart.id for chart in registry]

        # Assert
        assert "chart1" in chart_ids
        assert "chart2" in chart_ids
        assert "active1" not in chart_ids

    def test_len_returns_predefined_count_only(self, registry: ChartRegistry) -> None:
        """__len__ returns count of predefined charts only."""
        # Arrange - registry has 2 predefined from fixture

        # Act
        count = len(registry)

        # Assert
        assert count == 2


class TestChartRegistryDatasetType:
    """Tests for ChartRegistry dataset type handling."""

    def test_stores_dataset_type_correctly(self) -> None:
        """ChartRegistry stores dataset_type from constructor."""
        # Arrange & Act
        registry = ChartRegistry(CollectionName.FIPS140)

        # Assert
        assert registry.dataset_type == CollectionName.FIPS140

    @pytest.mark.parametrize("collection", list(CollectionName))
    def test_accepts_all_collection_types(self, collection: CollectionName) -> None:
        """ChartRegistry accepts any CollectionName value."""
        # Arrange & Act
        registry = ChartRegistry(collection)

        # Assert
        assert registry.dataset_type == collection
