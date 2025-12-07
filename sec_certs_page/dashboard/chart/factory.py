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
from ..types.chart import AvailableChartTypes


class ChartFactory:
    """Factory that creates BaseChart instances from Chart configurations."""

    _chart_classes: dict[AvailableChartTypes, type[BaseChart]] = {
        AvailableChartTypes.BAR: BarChartComponent,
        AvailableChartTypes.STACKED_BAR: BarChartComponent,  # Stacked bar uses same component
        AvailableChartTypes.LINE: LineChartComponent,
        AvailableChartTypes.PIE: PieChartComponent,
        AvailableChartTypes.SCATTER: ScatterChartComponent,
        AvailableChartTypes.BOX: BoxChartComponent,
        AvailableChartTypes.HISTOGRAM: HistogramChartComponent,
    }

    @classmethod
    def create_chart(cls, config: ChartConfig) -> BaseChart:
        """Create a BaseChart instance from a Chart configuration."""
        chart_class = cls._chart_classes.get(config.chart_type)
        if not chart_class:
            raise ValueError(f"Unknown chart type: {config.chart_type}")

        return chart_class(config=config)
