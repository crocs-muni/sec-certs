from ..chart.base import BaseChart
from .config import ChartConfig
from .chart import (
    BarChartComponent,
    BoxChartComponent,
    HistogramChartComponent,
    LineChartComponent,
    PieChartComponent,
    ScatterChartComponent,
)
from ..types.chart import ChartType


class ChartFactory:
    """Factory that creates BaseChart instances from Chart configurations."""

    _chart_classes: dict[ChartType, type[BaseChart]] = {
        ChartType.BAR: BarChartComponent,
        ChartType.STACKED_BAR: BarChartComponent,  # Stacked bar uses same component
        ChartType.LINE: LineChartComponent,
        ChartType.PIE: PieChartComponent,
        ChartType.SCATTER: ScatterChartComponent,
        ChartType.BOX: BoxChartComponent,
        ChartType.HISTOGRAM: HistogramChartComponent,
    }

    @classmethod
    def create_chart(cls, config: ChartConfig) -> BaseChart:
        """Create a BaseChart instance from a Chart configuration."""
        chart_class = cls._chart_classes.get(config.chart_type)
        if not chart_class:
            raise ValueError(f"Unknown chart type: {config.chart_type}")

        return chart_class(config=config)
