from dataclasses import dataclass


@dataclass
class Chart:
    """
    Represents a chart configuration within a dashboard.

    :param chart_id: Unique identifier for the chart.
    :param title: Title of the chart.
    :param chart_type: Type of the chart (e.g., 'bar', 'line', 'pie').
    """

    ...


class ChartConfig:
    """
    Configuration details for a chart.

    :param config: A dictionary containing chart configuration parameters.
    """

    ...
