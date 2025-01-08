# sec_certs_page/common/dashboard/types.py
from typing import Any, Dict, Generic, List, Literal, TypedDict, TypeVar

ChartType = Literal["pie", "bar", "line"]

T_ChartConfig = TypeVar("T_ChartConfig", bound="ChartConfig")


class ChartConfig(TypedDict):
    id: str
    title: str
    type: ChartType
    options: Dict[str, Any]


class BaseDashboardConfig(TypedDict, Generic[T_ChartConfig]):
    id: str
    title: str
    refresh_interval: int
    charts: List[T_ChartConfig]
