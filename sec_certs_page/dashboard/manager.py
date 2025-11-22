from sec_certs_page.dashboard.charts.registry import ChartRegistry
from sec_certs_page.dashboard.layout import DashboardLayout
from sec_certs_page.dashboard.types.common import DatasetTypeName
from sec_certs_page.dashboard.types.dashboard import Dashboard


class DashboardManager:
    """
    Central registry for creating Dashboard layout and providing methods serializing Dashboard state.
    """

    def __init__(self) -> None:
        self.chart_registries: dict[DatasetTypeName, ChartRegistry] = self.create_chart_registries()

    def create_chart_registries(self) -> dict[DatasetTypeName, ChartRegistry]:
        """
        Create chart registries for all supported dataset types.

        :return: A dictionary mapping dataset types to their corresponding ChartRegistry instances.
        """
        if self.chart_registries:
            return self.chart_registries
        registries: dict[DatasetTypeName, ChartRegistry] = {}
        for dataset_type in DatasetTypeName:
            registries[dataset_type] = ChartRegistry(dataset_type=dataset_type)
        return registries

    def get_chart_registry(self, dataset_type: DatasetTypeName) -> ChartRegistry:
        """
        Retrieve the ChartRegistry for a specific dataset type.

        :param dataset_type: The dataset type for which to retrieve the ChartRegistry.
        :return: The corresponding ChartRegistry instance.
        """
        return self.chart_registries[dataset_type]

    def create(self) -> Dashboard:
        """

        :return: An instance of Dashboard.
        """
        dashboard_layout = DashboardLayout()

        return
