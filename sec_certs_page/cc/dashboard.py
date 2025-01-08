# sec_certs_page/cc/dashboard.py
from dash import Input, Output

from ..common.dashboard.base import BaseChart, BaseDashboard
from ..common.dashboard.types import ChartConfig
from . import get_cc_analysis
from .charts import CCBarChart, CCPieChart
from .types import CCDashboardConfig


class CCDashboard(BaseDashboard[CCDashboardConfig]):
    """Dashboard for Common Criteria certificates."""

    def create_chart(self, config: ChartConfig) -> BaseChart | None:
        """Create a CC chart based on configuration."""
        chart_types = {"pie": CCPieChart, "bar": CCBarChart}
        chart_class = chart_types.get(config["type"])
        if chart_class:
            return chart_class(config)
        return None

    def register_callbacks(self, app):
        """Register callbacks for chart updates."""

        @app.callback(
            [Output(chart.id, "figure") for chart in self.charts.values()], Input("interval-component", "n_intervals")
        )
        def update_charts(_):
            data = get_cc_analysis()
            for chart in self.charts.values():
                chart.update(data)
            return [chart.figure for chart in self.charts.values()]
