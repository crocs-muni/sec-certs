"""Unit tests for ChartRegistry class.

Tests chart registration, lookup, and iteration through public APIs.
"""

import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

import pytest
from dash.development.base_component import Component

from sec_certs_page.dashboard.chart.base import BaseChart
from sec_certs_page.dashboard.chart.config import AxisConfig
from sec_certs_page.dashboard.chart.config import ChartConfig as Chart
from sec_certs_page.dashboard.chart.registry import ChartRegistry
from sec_certs_page.dashboard.types.chart import ChartType
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
                chart_type=ChartType.BAR,
                collection_name=CollectionName.CommonCriteria,
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
        assert registry.get_predefined(chart.id) == chart

    def test_register_with_duplicate_id_raises_value_error(self, registry: ChartRegistry) -> None:
        """register raises ValueError when chart ID already exists."""
        # Arrange
        chart1 = FakeChart(graph_id="duplicate-id")
        # Ensure chart2 has same ID as chart1
        chart2 = FakeChart(graph_id="duplicate-id")
        chart2.config.chart_id = chart1.config.chart_id

        registry.register(chart1)

        # Act & Assert
        with pytest.raises(ValueError, match="already registered"):
            registry.register(chart2)

    def test_register_with_empty_id_succeeds(self, registry: ChartRegistry) -> None:
        """register accepts chart with empty string ID."""
        # Arrange
        chart = FakeChart(graph_id="")

        # Act
        registry.register(chart)

        # Assert
        assert registry.get_predefined(chart.id) == chart


class TestChartRegistryLookup:
    """Tests for ChartRegistry lookup operations."""

    @pytest.fixture
    def registry(self) -> ChartRegistry:
        """Create a ChartRegistry with predefined charts."""
        registry = ChartRegistry(CollectionName.CommonCriteria)
        registry.register(FakeChart(graph_id="predefined-chart"))
        return registry

    def test_get_predefined_returns_chart_for_valid_id(self, registry: ChartRegistry) -> None:
        """get_predefined returns chart when ID exists."""
        # Arrange
        chart = FakeChart(graph_id="test-chart")
        registry.register(chart)

        # Act
        result = registry.get_predefined(chart.id)

        # Assert
        assert result == chart

    def test_get_predefined_returns_none_for_nonexistent_id(self, registry: ChartRegistry) -> None:
        """get_predefined returns None when ID does not exist."""
        # Act
        result = registry.get_predefined("nonexistent")

        # Assert
        assert result is None

    def test_getitem_returns_chart_for_valid_id(self, registry: ChartRegistry) -> None:
        """__getitem__ returns chart when ID exists."""
        # Arrange
        chart = FakeChart(graph_id="test-chart")
        registry.register(chart)

        # Act
        result = registry[chart.id]

        # Assert
        assert result == chart

    def test_getitem_raises_key_error_for_nonexistent_id(self, registry: ChartRegistry) -> None:
        """__getitem__ raises KeyError when ID not found."""
        # Arrange - registry does not have "nonexistent"
        with pytest.raises(KeyError):
            _ = registry["nonexistent"]


class TestChartRegistryIteration:
    """Tests for ChartRegistry iteration and length."""

    @pytest.fixture
    def registry(self) -> ChartRegistry:
        """Create a ChartRegistry with charts."""
        registry = ChartRegistry(CollectionName.CommonCriteria)
        registry.register(FakeChart(graph_id="chart1"))
        registry.register(FakeChart(graph_id="chart2"))
        return registry

    def test_iter_yields_only_predefined_charts(self, registry: ChartRegistry) -> None:
        """__iter__ yields predefined charts."""
        # Arrange - registry has 2 predefined charts

        # Act
        charts = list(registry)

        # Assert
        assert len(charts) == 2

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
        """ChartRegistry stores collection_name from constructor."""
        # Arrange & Act
        registry = ChartRegistry(CollectionName.FIPS140)

        # Assert
        assert registry.collection_name == CollectionName.FIPS140

    @pytest.mark.parametrize("collection", list(CollectionName))
    def test_accepts_all_collection_types(self, collection: CollectionName) -> None:
        """ChartRegistry accepts any CollectionName value."""
        # Arrange & Act
        registry = ChartRegistry(collection)

        # Assert
        assert registry.collection_name == collection
