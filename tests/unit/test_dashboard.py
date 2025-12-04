"""Unit tests for Dashboard class.

Tests dashboard serialization and chart management through public APIs only.
"""

import uuid
from datetime import datetime, timezone
from typing import Any

import pytest

from sec_certs_page.dashboard.chart.chart import AxisConfig, Chart
from sec_certs_page.dashboard.dashboard import Dashboard
from sec_certs_page.dashboard.types.chart import AvailableChartTypes
from sec_certs_page.dashboard.types.common import CollectionName


class TestDashboardCreation:
    """Tests for Dashboard initialization."""

    def test_create_dashboard_with_required_fields_succeeds(self) -> None:
        """Dashboard created with user_id and collection_name has valid ID."""
        # Arrange
        user_id = "user123"
        collection = CollectionName.CommonCriteria

        # Act
        dashboard = Dashboard(user_id=user_id, collection_name=collection)

        # Assert
        assert isinstance(dashboard.dashboard_id, uuid.UUID)
        assert dashboard.user_id == user_id
        assert dashboard.collection_name == collection

    def test_create_dashboard_with_defaults_uses_expected_values(self) -> None:
        """Dashboard uses expected default values when optional fields omitted."""
        # Arrange & Act
        dashboard = Dashboard(
            user_id="user123",
            collection_name=CollectionName.CommonCriteria,
        )

        # Assert
        assert dashboard.name == "New dashboard"
        assert dashboard.description is None
        assert dashboard.charts == []
        assert dashboard.is_default is False

    def test_create_dashboard_same_inputs_produces_same_id(self) -> None:
        """Dashboard ID is deterministic for same user, collection, and timestamp."""
        # Arrange
        created_at = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)

        # Act
        dashboard1 = Dashboard(
            user_id="user123",
            collection_name=CollectionName.CommonCriteria,
            created_at=created_at,
        )
        dashboard2 = Dashboard(
            user_id="user123",
            collection_name=CollectionName.CommonCriteria,
            created_at=created_at,
        )

        # Assert
        assert dashboard1.dashboard_id == dashboard2.dashboard_id

    def test_create_dashboard_different_users_produces_different_ids(self) -> None:
        """Different users get different dashboard IDs even with same timestamp."""
        # Arrange
        created_at = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)

        # Act
        dashboard1 = Dashboard(
            user_id="user1",
            collection_name=CollectionName.CommonCriteria,
            created_at=created_at,
        )
        dashboard2 = Dashboard(
            user_id="user2",
            collection_name=CollectionName.CommonCriteria,
            created_at=created_at,
        )

        # Assert
        assert dashboard1.dashboard_id != dashboard2.dashboard_id

    def test_create_dashboard_different_collections_produces_different_ids(self) -> None:
        """Different collections produce different dashboard IDs for same user."""
        # Arrange
        created_at = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)

        # Act
        dashboard1 = Dashboard(
            user_id="user123",
            collection_name=CollectionName.CommonCriteria,
            created_at=created_at,
        )
        dashboard2 = Dashboard(
            user_id="user123",
            collection_name=CollectionName.FIPS140,
            created_at=created_at,
        )

        # Assert
        assert dashboard1.dashboard_id != dashboard2.dashboard_id

    def test_create_dashboard_with_empty_user_id_succeeds(self) -> None:
        """Dashboard can be created with empty string user_id."""
        # Arrange & Act
        dashboard = Dashboard(
            user_id="",
            collection_name=CollectionName.CommonCriteria,
        )

        # Assert
        assert dashboard.user_id == ""
        assert isinstance(dashboard.dashboard_id, uuid.UUID)


class TestDashboardSerialization:
    """Tests for Dashboard to_dict/from_dict serialization."""

    def test_to_dict_includes_all_required_fields(self) -> None:
        """to_dict returns dictionary with all required dashboard fields."""
        # Arrange
        dashboard = Dashboard(
            user_id="user123",
            collection_name=CollectionName.CommonCriteria,
            name="My Dashboard",
            description="Test description",
            is_default=True,
        )

        # Act
        result = dashboard.to_dict()

        # Assert
        assert result["user_id"] == "user123"
        assert result["collection_name"] == "cc"
        assert result["name"] == "My Dashboard"
        assert result["description"] == "Test description"
        assert result["is_default"] is True
        assert "dashboard_id" in result
        assert "created_at" in result

    def test_to_dict_serializes_empty_charts_as_empty_list(self) -> None:
        """to_dict returns empty list when dashboard has no charts."""
        # Arrange
        dashboard = Dashboard(
            user_id="user123",
            collection_name=CollectionName.CommonCriteria,
        )

        # Act
        result = dashboard.to_dict()

        # Assert
        assert result["charts"] == []

    def test_from_dict_restores_all_fields(self) -> None:
        """from_dict correctly restores dashboard from serialized data."""
        # Arrange
        data: dict[str, Any] = {
            "dashboard_id": "12345678-1234-5678-1234-567812345678",
            "user_id": "user123",
            "collection_name": "cc",
            "name": "Restored Dashboard",
            "description": "Restored description",
            "is_default": True,
            "charts": [],
            "created_at": "2024-01-15T10:30:00+00:00",
            "updated_at": "2024-01-15T10:30:00+00:00",
        }

        # Act
        dashboard = Dashboard.from_dict(data)

        # Assert
        assert dashboard.user_id == "user123"
        assert dashboard.collection_name == CollectionName.CommonCriteria
        assert dashboard.name == "Restored Dashboard"
        assert dashboard.description == "Restored description"
        assert dashboard.is_default is True

    def test_from_dict_with_missing_user_id_raises_value_error(self) -> None:
        """from_dict raises ValueError when user_id is missing."""
        # Arrange
        data: dict[str, Any] = {
            "dashboard_id": "12345678-1234-5678-1234-567812345678",
            "collection_name": "cc",
            "name": "Missing Fields",
            "charts": [],
            "created_at": "2024-01-15T10:30:00+00:00",
            "updated_at": "2024-01-15T10:30:00+00:00",
        }

        # Act & Assert
        with pytest.raises(ValueError, match="Missing required fields"):
            Dashboard.from_dict(data)

    def test_from_dict_with_missing_collection_name_raises_value_error(self) -> None:
        """from_dict raises ValueError when collection_name is missing."""
        # Arrange
        data: dict[str, Any] = {
            "dashboard_id": "12345678-1234-5678-1234-567812345678",
            "user_id": "user123",
            "name": "Missing Fields",
            "charts": [],
            "created_at": "2024-01-15T10:30:00+00:00",
            "updated_at": "2024-01-15T10:30:00+00:00",
        }

        # Act & Assert
        with pytest.raises(ValueError, match="Missing required fields"):
            Dashboard.from_dict(data)

    def test_roundtrip_serialization_preserves_data(self) -> None:
        """to_dict followed by from_dict preserves all dashboard data."""
        # Arrange
        original = Dashboard(
            user_id="user123",
            collection_name=CollectionName.FIPS140,
            name="Roundtrip Test",
            description="Test roundtrip",
            is_default=True,
        )

        # Act
        restored = Dashboard.from_dict(original.to_dict())

        # Assert
        assert restored.user_id == original.user_id
        assert restored.collection_name == original.collection_name
        assert restored.name == original.name
        assert restored.description == original.description
        assert restored.is_default == original.is_default

    def test_from_dict_with_charts_restores_chart_objects(self) -> None:
        """from_dict correctly restores Chart objects from serialized data."""
        # Arrange
        chart_data: dict[str, Any] = {
            "chart_id": "12345678-1234-5678-1234-567812345678",
            "name": "test-chart",
            "title": "Test Chart",
            "chart_type": "bar",
            "collection_type": "cc",
            "x_axis": {"field": "category", "label": "Category"},
            "created_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-01-15T10:30:00Z",
        }
        data: dict[str, Any] = {
            "dashboard_id": "12345678-1234-5678-1234-567812345678",
            "user_id": "user123",
            "collection_name": "cc",
            "name": "With Charts",
            "charts": [chart_data],
            "created_at": "2024-01-15T10:30:00+00:00",
            "updated_at": "2024-01-15T10:30:00+00:00",
        }

        # Act
        dashboard = Dashboard.from_dict(data)

        # Assert
        assert len(dashboard.charts) == 1
        assert dashboard.charts[0].title == "Test Chart"
        assert dashboard.charts[0].name == "test-chart"

    def test_from_dict_handles_z_suffix_datetime(self) -> None:
        """from_dict correctly parses datetime with 'Z' suffix."""
        # Arrange
        data: dict[str, Any] = {
            "dashboard_id": "12345678-1234-5678-1234-567812345678",
            "user_id": "user123",
            "collection_name": "cc",
            "name": "Z Suffix Test",
            "charts": [],
            "created_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-01-15T10:30:00Z",
        }

        # Act
        dashboard = Dashboard.from_dict(data)

        # Assert
        assert dashboard.created_at.year == 2024
        assert dashboard.created_at.month == 1
        assert dashboard.created_at.day == 15

    def test_from_dict_handles_corrupted_double_timezone(self) -> None:
        """from_dict handles corrupted datetime with double timezone suffix."""
        # Arrange
        data: dict[str, Any] = {
            "dashboard_id": "12345678-1234-5678-1234-567812345678",
            "user_id": "user123",
            "collection_name": "cc",
            "name": "Corrupted TZ Test",
            "charts": [],
            "created_at": "2024-01-15T10:30:00+00:00+00:00",
            "updated_at": "2024-01-15T10:30:00+00:00",
        }

        # Act
        dashboard = Dashboard.from_dict(data)

        # Assert
        assert dashboard.created_at.year == 2024
        assert dashboard.created_at.hour == 10

    def test_from_dict_with_none_description_restores_none(self) -> None:
        """from_dict restores None description correctly."""
        # Arrange
        data: dict[str, Any] = {
            "dashboard_id": "12345678-1234-5678-1234-567812345678",
            "user_id": "user123",
            "collection_name": "cc",
            "name": "No Description",
            "description": None,
            "charts": [],
            "created_at": "2024-01-15T10:30:00+00:00",
            "updated_at": "2024-01-15T10:30:00+00:00",
        }

        # Act
        dashboard = Dashboard.from_dict(data)

        # Assert
        assert dashboard.description is None

    def test_from_dict_with_empty_string_description_restores_empty_string(self) -> None:
        """from_dict restores empty string description correctly."""
        # Arrange
        data: dict[str, Any] = {
            "dashboard_id": "12345678-1234-5678-1234-567812345678",
            "user_id": "user123",
            "collection_name": "cc",
            "name": "Empty Description",
            "description": "",
            "charts": [],
            "created_at": "2024-01-15T10:30:00+00:00",
            "updated_at": "2024-01-15T10:30:00+00:00",
        }

        # Act
        dashboard = Dashboard.from_dict(data)

        # Assert
        assert dashboard.description == ""


class TestDashboardChartManagement:
    """Tests for Dashboard chart add/remove/update operations."""

    @pytest.fixture
    def dashboard(self) -> Dashboard:
        """Create a dashboard for testing."""
        return Dashboard(
            user_id="user123",
            collection_name=CollectionName.CommonCriteria,
        )

    @pytest.fixture
    def sample_chart(self) -> Chart:
        """Create a sample chart for testing."""
        return Chart(
            chart_id=uuid.UUID("12345678-1234-5678-1234-567812345678"),
            name="test-chart",
            title="Test Chart",
            chart_type=AvailableChartTypes.BAR,
            collection_type=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
        )

    def test_add_chart_appends_chart_to_list(self, dashboard: Dashboard, sample_chart: Chart) -> None:
        """add_chart appends chart to dashboard's charts list."""
        # Arrange - fixtures provide dashboard and sample_chart

        # Act
        dashboard.add_chart(sample_chart)

        # Assert
        assert len(dashboard.charts) == 1
        assert dashboard.charts[0] == sample_chart

    def test_add_chart_updates_timestamp(self, dashboard: Dashboard, sample_chart: Chart) -> None:
        """add_chart updates dashboard's updated_at timestamp."""
        # Arrange
        original_updated = dashboard.updated_at

        # Act
        dashboard.add_chart(sample_chart)

        # Assert
        assert dashboard.updated_at >= original_updated

    def test_remove_chart_with_valid_id_removes_chart(self, dashboard: Dashboard, sample_chart: Chart) -> None:
        """remove_chart removes and returns chart with matching ID."""
        # Arrange
        dashboard.add_chart(sample_chart)

        # Act
        removed = dashboard.remove_chart(str(sample_chart.chart_id))

        # Assert
        assert len(dashboard.charts) == 0
        assert removed == sample_chart

    def test_remove_chart_with_nonexistent_id_raises_value_error(self, dashboard: Dashboard) -> None:
        """remove_chart raises ValueError for non-existent chart ID."""
        # Arrange
        nonexistent_uuid = "00000000-0000-0000-0000-000000000000"

        # Act & Assert
        with pytest.raises(ValueError, match="not found"):
            dashboard.remove_chart(nonexistent_uuid)

    def test_get_chart_with_valid_id_returns_chart(self, dashboard: Dashboard, sample_chart: Chart) -> None:
        """get_chart returns chart with matching ID."""
        # Arrange
        dashboard.add_chart(sample_chart)

        # Act
        result = dashboard.get_chart(str(sample_chart.chart_id))

        # Assert
        assert result == sample_chart

    def test_get_chart_with_nonexistent_id_returns_none(self, dashboard: Dashboard) -> None:
        """get_chart returns None when chart ID not found."""
        # Arrange
        nonexistent_uuid = "00000000-0000-0000-0000-000000000000"

        # Act
        result = dashboard.get_chart(nonexistent_uuid)

        # Assert
        assert result is None

    def test_update_chart_replaces_existing_chart(self, dashboard: Dashboard, sample_chart: Chart) -> None:
        """update_chart replaces chart with matching ID."""
        # Arrange
        dashboard.add_chart(sample_chart)
        updated_chart = Chart(
            chart_id=sample_chart.chart_id,
            name="updated-chart",
            title="Updated Title",
            chart_type=AvailableChartTypes.LINE,
            collection_type=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="year", label="Year"),
        )

        # Act
        dashboard.update_chart(updated_chart)

        # Assert
        assert dashboard.charts[0].title == "Updated Title"
        assert dashboard.charts[0].chart_type == AvailableChartTypes.LINE

    def test_update_chart_with_nonexistent_id_raises_value_error(
        self, dashboard: Dashboard, sample_chart: Chart
    ) -> None:
        """update_chart raises ValueError for non-existent chart."""
        # Arrange - sample_chart is not added to dashboard

        # Act & Assert
        with pytest.raises(ValueError, match="not found"):
            dashboard.update_chart(sample_chart)

    def test_clear_charts_removes_all_charts(self, dashboard: Dashboard, sample_chart: Chart) -> None:
        """clear_charts removes all charts from dashboard."""
        # Arrange
        dashboard.add_chart(sample_chart)
        dashboard.add_chart(
            Chart(
                chart_id=uuid.uuid4(),
                name="another-chart",
                title="Another Chart",
                chart_type=AvailableChartTypes.PIE,
                collection_type=CollectionName.CommonCriteria,
                x_axis=AxisConfig(field="scheme", label="Scheme"),
            )
        )

        # Act
        dashboard.clear_charts()

        # Assert
        assert len(dashboard.charts) == 0

    def test_clear_charts_on_empty_dashboard_succeeds(self, dashboard: Dashboard) -> None:
        """clear_charts on dashboard with no charts does not raise."""
        # Arrange - dashboard starts empty

        # Act
        dashboard.clear_charts()

        # Assert
        assert len(dashboard.charts) == 0
