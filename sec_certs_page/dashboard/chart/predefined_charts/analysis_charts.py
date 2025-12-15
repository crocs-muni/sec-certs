"""Advanced analysis chart definitions.

This module provides predefined charts for deeper analysis of certification data,
including cross-dimensional analysis and temporal trends.

Charts included:
- CC EAL Distribution by Category (stacked bar)
- FIPS Security Level by Module Type (stacked bar)
- CC Certification Trends Over Time (line chart by category)
"""

from uuid import uuid4

from ...types.chart import ChartType
from ...types.common import CollectionName
from ...types.filter import AggregationType
from ..config import AxisConfig, ChartConfig
from ..factory import ChartFactory


def create_cc_analysis_charts() -> list:
    """Create CC analysis charts for deeper insights.

    These charts use cross-dimensional analysis to reveal patterns
    in certification data that aren't visible in single-dimension charts.
    """
    charts = []

    # EAL Distribution by Category - Stacked Bar
    # Shows which categories tend to have higher assurance levels
    eal_by_category_config = ChartConfig(
        chart_id=uuid4(),
        name="cc-eal-distribution-by-category",
        title="EAL Distribution by Category",
        chart_type=ChartType.STACKED_BAR,
        collection_name=CollectionName.CommonCriteria,
        x_axis=AxisConfig(field="category", label="Product Category"),
        y_axis=AxisConfig(field="count", label="Number of Certificates", aggregation=AggregationType.COUNT),
        color_axis=AxisConfig(field="heuristics.eal", label="EAL Level"),
        show_legend=True,
        show_grid=True,
        show_zero_values=False,
    )
    charts.append(ChartFactory.create_chart(eal_by_category_config))

    # Certification Trends by Category Over Time - Line Chart
    # Shows how certification activity evolves across categories
    trends_by_category_config = ChartConfig(
        chart_id=uuid4(),
        name="cc-trends-by-category",
        title="Certification Trends by Category",
        chart_type=ChartType.LINE,
        collection_name=CollectionName.CommonCriteria,
        x_axis=AxisConfig(field="year_from", label="Year"),
        y_axis=AxisConfig(field="count", label="Certificates Issued", aggregation=AggregationType.COUNT),
        color_axis=AxisConfig(field="category", label="Category"),
        show_legend=True,
        show_grid=True,
    )
    charts.append(ChartFactory.create_chart(trends_by_category_config))

    # Certification by Scheme Over Time - Stacked Bar
    # Shows regional certification activity patterns
    scheme_trends_config = ChartConfig(
        chart_id=uuid4(),
        name="cc-scheme-trends",
        title="Certifications by Scheme Over Time",
        chart_type=ChartType.STACKED_BAR,
        collection_name=CollectionName.CommonCriteria,
        x_axis=AxisConfig(field="year_from", label="Year"),
        y_axis=AxisConfig(field="count", label="Certificates Issued", aggregation=AggregationType.COUNT),
        color_axis=AxisConfig(field="scheme", label="Certification Scheme"),
        show_legend=True,
        show_grid=True,
    )
    charts.append(ChartFactory.create_chart(scheme_trends_config))

    return charts


def create_fips_analysis_charts() -> list:
    """Create FIPS analysis charts for deeper insights.

    These charts reveal patterns in FIPS certification data including
    the relationship between module types and security levels.
    """
    charts = []

    # Security Level by Module Type - Stacked Bar
    # Reveals that hardware modules tend to achieve higher security levels
    level_by_type_config = ChartConfig(
        chart_id=uuid4(),
        name="fips-level-by-module-type",
        title="Security Level Distribution by Module Type",
        chart_type=ChartType.STACKED_BAR,
        collection_name=CollectionName.FIPS140,
        x_axis=AxisConfig(field="web_data.module_type", label="Module Type"),
        y_axis=AxisConfig(field="count", label="Number of Modules", aggregation=AggregationType.COUNT),
        color_axis=AxisConfig(field="web_data.level", label="Security Level"),
        show_legend=True,
        show_grid=True,
        show_zero_values=False,
    )
    charts.append(ChartFactory.create_chart(level_by_type_config))

    # FIPS Standard Migration Over Time - Stacked Bar
    # Shows the transition from FIPS 140-1 → 140-2 → 140-3
    standard_trends_config = ChartConfig(
        chart_id=uuid4(),
        name="fips-standard-migration",
        title="FIPS Standard Migration Over Time",
        chart_type=ChartType.STACKED_BAR,
        collection_name=CollectionName.FIPS140,
        x_axis=AxisConfig(field="year_from", label="Year"),
        y_axis=AxisConfig(field="count", label="Modules Validated", aggregation=AggregationType.COUNT),
        color_axis=AxisConfig(field="web_data.standard", label="FIPS Standard"),
        show_legend=True,
        show_grid=True,
    )
    charts.append(ChartFactory.create_chart(standard_trends_config))

    # Module Type Distribution by Status - Stacked Bar
    # Shows which module types tend to become historical vs stay active
    type_by_status_config = ChartConfig(
        chart_id=uuid4(),
        name="fips-type-by-status",
        title="Module Type Distribution by Status",
        chart_type=ChartType.STACKED_BAR,
        collection_name=CollectionName.FIPS140,
        x_axis=AxisConfig(field="web_data.module_type", label="Module Type"),
        y_axis=AxisConfig(field="count", label="Number of Modules", aggregation=AggregationType.COUNT),
        color_axis=AxisConfig(field="web_data.status", label="Certificate Status"),
        show_legend=True,
        show_grid=True,
        show_zero_values=False,
    )
    charts.append(ChartFactory.create_chart(type_by_status_config))

    return charts
