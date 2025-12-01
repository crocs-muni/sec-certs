from datetime import datetime
from enum import Enum
from typing import Any, TypedDict
from uuid import UUID


class AvailableChartTypes(str, Enum):
    BAR = "bar"
    STACKED_BAR = "stacked_bar"
    LINE = "line"
    PIE = "pie"
    SCATTER = "scatter"
    BOX = "box"
    HISTOGRAM = "histogram"


class ChartDict(TypedDict):
    chart_id: UUID
    title: str
    name: str
    order: int
    chart_type: AvailableChartTypes
    x_axis: dict[str, Any]
    y_axis: dict[str, Any] | None
    color_axis: dict[str, Any] | None
    filters: dict[str, Any]
    color_scheme: str
    show_legend: bool
    show_grid: bool
    query_pipeline: list[dict[str, Any]] | None
    created_at: datetime | None
    updated_at: datetime | None
