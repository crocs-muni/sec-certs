from uuid import uuid4

import pandas as pd
import plotly.graph_objects as go
import pytest

from sec_certs_page.dashboard.chart.config import AxisConfig
from sec_certs_page.dashboard.chart.config import ChartConfig as Chart
from sec_certs_page.dashboard.chart.figure_builder import FigureBuilder
from sec_certs_page.dashboard.types.chart import ChartType
from sec_certs_page.dashboard.types.common import CollectionName
from sec_certs_page.dashboard.types.filter import AggregationType


class TestFigureBuilderCreateFigure:
    """Tests for FigureBuilder.create_figure public API."""

    @pytest.fixture
    def sample_data(self) -> pd.DataFrame:
        """Create sample certificate data for testing."""
        return pd.DataFrame(
            {
                "category": ["ICs", "ICs", "Software", "Software", "Network"],
                "scheme": ["DE", "FR", "DE", "FR", "DE"],
                "year_from": [2020, 2021, 2020, 2022, 2021],
                "eal_level": [4, 5, 3, 4, 5],
            }
        )

    def test_create_figure_bar_chart_returns_figure(self, sample_data: pd.DataFrame) -> None:
        """create_figure returns go.Figure for bar chart."""
        config = Chart(
            chart_id=uuid4(),
            name="test-bar-chart",
            title="Certificates by Category",
            chart_type=ChartType.BAR,
            collection_name=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
            y_axis=AxisConfig(field="count", label="Count", aggregation=AggregationType.COUNT),
        )

        fig = FigureBuilder.create_figure(config, sample_data)

        assert isinstance(fig, go.Figure)
        assert fig.layout.title.text == "Certificates by Category"

    def test_create_figure_line_chart_returns_figure(self, sample_data: pd.DataFrame) -> None:
        """create_figure returns go.Figure for line chart."""
        config = Chart(
            chart_id=uuid4(),
            name="test-line-chart",
            title="Certificates Over Time",
            chart_type=ChartType.LINE,
            collection_name=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="year_from", label="Year"),
            y_axis=AxisConfig(field="count", label="Count", aggregation=AggregationType.COUNT),
        )

        fig = FigureBuilder.create_figure(config, sample_data)

        assert isinstance(fig, go.Figure)
        assert fig.layout.title.text == "Certificates Over Time"

    def test_create_figure_pie_chart_returns_figure(self, sample_data: pd.DataFrame) -> None:
        """create_figure returns go.Figure for pie chart."""
        config = Chart(
            chart_id=uuid4(),
            name="test-pie-chart",
            title="Distribution by Scheme",
            chart_type=ChartType.PIE,
            collection_name=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="scheme", label="Scheme"),
            y_axis=AxisConfig(field="count", label="Count", aggregation=AggregationType.COUNT),
        )

        fig = FigureBuilder.create_figure(config, sample_data)

        assert isinstance(fig, go.Figure)
        assert fig.layout.title.text == "Distribution by Scheme"

    def test_create_figure_applies_log_scale(self, sample_data: pd.DataFrame) -> None:
        """create_figure applies log scale to axes when configured."""
        config = Chart(
            chart_id=uuid4(),
            name="test-log-scale-chart",
            title="Log Scale Chart",
            chart_type=ChartType.BAR,
            collection_name=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
            y_axis=AxisConfig(field="count", label="Count", aggregation=AggregationType.COUNT, log_scale=True),
        )

        fig = FigureBuilder.create_figure(config, sample_data)

        assert fig.layout.yaxis.type == "log"

    def test_create_figure_filters_zero_values(self, sample_data: pd.DataFrame) -> None:
        """create_figure filters out zero values when show_zero_values is False."""
        # Create data with zero values
        df = pd.DataFrame(
            {
                "category": ["A", "B", "C"],
                "Count": [10, 0, 5],
            }
        )

        config = Chart(
            chart_id=uuid4(),
            name="test-zero-values-chart",
            title="Zero Values Chart",
            chart_type=ChartType.BAR,
            collection_name=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
            y_axis=AxisConfig(field="count", label="Count", aggregation=AggregationType.COUNT),
            show_zero_values=False,
        )
        fig = FigureBuilder.create_figure_from_aggregated(config, df)

        assert "B" not in fig.data[0].x

    @pytest.mark.parametrize(
        "chart_type",
        [
            ChartType.BAR,
            ChartType.LINE,
            ChartType.PIE,
            ChartType.SCATTER,
            ChartType.BOX,
            ChartType.HISTOGRAM,
        ],
    )
    def test_create_figure_all_chart_types_return_figures(
        self, chart_type: ChartType, sample_data: pd.DataFrame
    ) -> None:
        """create_figure produces valid Figure for all supported chart types."""
        y_field = "count"
        y_agg = AggregationType.COUNT

        if chart_type == ChartType.BOX:
            y_field = "eal_level"
            y_agg = None

        config = Chart(
            chart_id=uuid4(),
            name=f"test-{chart_type.value}-chart",
            title=f"Test {chart_type.value} Chart",
            chart_type=chart_type,
            collection_name=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
            y_axis=AxisConfig(field=y_field, label="Y", aggregation=y_agg),
        )

        fig = FigureBuilder.create_figure(config, sample_data)

        assert isinstance(fig, go.Figure)
        assert fig.layout.title.text == f"Test {chart_type.value} Chart"

    def test_create_figure_applies_show_legend_false(self, sample_data: pd.DataFrame) -> None:
        """create_figure respects show_legend=False setting."""
        config = Chart(
            chart_id=uuid4(),
            name="no-legend-chart",
            title="No Legend",
            chart_type=ChartType.BAR,
            collection_name=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
            y_axis=AxisConfig(field="count", label="Count", aggregation=AggregationType.COUNT),
            show_legend=False,
        )

        fig = FigureBuilder.create_figure(config, sample_data)

        assert fig.layout.showlegend is False

    def test_create_figure_pie_without_y_axis_succeeds(self) -> None:
        """create_figure handles pie chart without y_axis."""
        df = pd.DataFrame({"status": ["Active", "Active", "Archived"]})
        config = Chart(
            chart_id=uuid4(),
            name="no-y-axis-chart",
            title="Status Distribution",
            chart_type=ChartType.PIE,
            collection_name=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="status", label="Status"),
        )

        fig = FigureBuilder.create_figure(config, df)

        assert isinstance(fig, go.Figure)


class TestChartFactoryEmptyAndErrorStates:
    """Tests for ChartFactory error handling (public API behavior)."""

    def test_create_figure_empty_dataframe_returns_empty_figure(self) -> None:
        """create_figure returns figure with 'No data' message for empty DataFrame."""
        config = Chart(
            chart_id=uuid4(),
            name="empty-data-chart",
            title="Empty",
            chart_type=ChartType.BAR,
            collection_name=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
            y_axis=AxisConfig(field="count", label="Count", aggregation=AggregationType.COUNT),
        )
        empty_df = pd.DataFrame()

        fig = FigureBuilder.create_figure(config, empty_df)

        assert isinstance(fig, go.Figure)
        assert len(fig.layout.annotations) > 0
        assert "No data" in fig.layout.annotations[0].text

    def test_create_figure_missing_field_returns_error_figure(self) -> None:
        """create_figure returns figure with error message when field not in data."""
        df = pd.DataFrame({"existing_field": [1, 2, 3]})
        config = Chart(
            chart_id=uuid4(),
            name="missing-field-chart",
            title="Missing Field",
            chart_type=ChartType.BAR,
            collection_name=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="nonexistent_field", label="Missing"),
            y_axis=AxisConfig(field="count", label="Count", aggregation=AggregationType.COUNT),
        )

        fig = FigureBuilder.create_figure(config, df)

        assert isinstance(fig, go.Figure)
        assert len(fig.layout.annotations) > 0
        assert "Error" in fig.layout.annotations[0].text


class TestChartFactoryAggregation:
    """Tests for ChartFactory data aggregation behavior via create_figure."""

    @pytest.fixture
    def numeric_data(self) -> pd.DataFrame:
        """Create sample data with numeric values for aggregation."""
        return pd.DataFrame(
            {
                "category": ["ICs", "ICs", "ICs", "Software", "Software"],
                "value": [10, 20, 30, 15, 25],
            }
        )

    def test_create_figure_count_aggregation_counts_rows(self, numeric_data: pd.DataFrame) -> None:
        """COUNT aggregation counts rows per group in figure."""
        config = Chart(
            chart_id=uuid4(),
            name="count-chart",
            title="Count",
            chart_type=ChartType.BAR,
            collection_name=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
            y_axis=AxisConfig(field="count", label="Count", aggregation=AggregationType.COUNT),
        )

        fig = FigureBuilder.create_figure(config, numeric_data)

        assert isinstance(fig, go.Figure)
        # Figure should be created successfully with aggregated data

    def test_create_figure_sum_aggregation_sums_values(self, numeric_data: pd.DataFrame) -> None:
        """SUM aggregation sums values per group in figure."""
        config = Chart(
            chart_id=uuid4(),
            name="sum-chart",
            title="Sum",
            chart_type=ChartType.BAR,
            collection_name=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
            y_axis=AxisConfig(field="value", label="Value", aggregation=AggregationType.SUM),
        )

        fig = FigureBuilder.create_figure(config, numeric_data)

        assert isinstance(fig, go.Figure)

    @pytest.mark.parametrize(
        "aggregation",
        [
            AggregationType.COUNT,
            AggregationType.SUM,
            AggregationType.AVG,
            AggregationType.MIN,
            AggregationType.MAX,
        ],
    )
    def test_create_figure_all_aggregations_produce_figures(
        self, aggregation: AggregationType, numeric_data: pd.DataFrame
    ) -> None:
        """All aggregation types produce valid figures."""
        y_field = "count" if aggregation == AggregationType.COUNT else "value"
        config = Chart(
            chart_id=uuid4(),
            name=f"agg-{aggregation.value}-chart",
            title=f"Aggregation {aggregation.value}",
            chart_type=ChartType.BAR,
            collection_name=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
            y_axis=AxisConfig(field=y_field, label="Value", aggregation=aggregation),
        )

        fig = FigureBuilder.create_figure(config, numeric_data)

        assert isinstance(fig, go.Figure)


class TestChartFactoryNaNHandling:
    """Tests for ChartFactory handling of NaN values."""

    def test_create_figure_with_nan_values_succeeds(self) -> None:
        """create_figure handles DataFrame with NaN values gracefully."""
        df = pd.DataFrame(
            {
                "category": ["A", "A", "B", "B"],
                "value": [10, float("nan"), 20, 30],
            }
        )
        config = Chart(
            chart_id=uuid4(),
            name="nan-chart",
            title="NaN Values",
            chart_type=ChartType.BAR,
            collection_name=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
            y_axis=AxisConfig(field="value", label="Value", aggregation=AggregationType.SUM),
        )

        fig = FigureBuilder.create_figure(config, df)

        assert isinstance(fig, go.Figure)
