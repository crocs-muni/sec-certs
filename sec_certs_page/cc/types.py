# sec_certs_page/cc/types.py
from ..common.dashboard.types import BaseDashboardConfig, ChartConfig


class CCChartConfig(ChartConfig):
    category_filter: str


class CCDashboardConfig(BaseDashboardConfig[CCChartConfig]):
    pass
