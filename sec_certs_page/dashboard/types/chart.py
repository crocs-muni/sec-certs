from enum import Enum


class ChartType(str, Enum):
    BAR = "bar"
    STACKED_BAR = "stacked_bar"
    LINE = "line"
    PIE = "pie"
    SCATTER = "scatter"
    BOX = "box"
    HISTOGRAM = "histogram"
