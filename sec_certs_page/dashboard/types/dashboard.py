from dataclasses import dataclass

from sec_certs_page.dashboard.charts.registry import ChartRegistry


@dataclass
class Dashboard:
    """
    Represents a dashboard configuration, including its chart registry.
    """

    charts: list[Chart] | None = None
    layout: str | None = None

    def to_json(self) -> dict:
        """
        Serializes the Dashboard instance to a JSON-compatible dictionary.

        :return: A dictionary representation of the Dashboard.
        """
        return {
            "charts": {"": ""} if self.chart_registry else None,
            "layout": self.layout,
        }
