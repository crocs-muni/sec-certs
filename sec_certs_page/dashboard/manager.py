import logging
from logging import Logger
from typing import Optional
from uuid import uuid4

from .chart.config import AxisConfig, ChartConfig
from .chart.error import ErrorChart
from .chart.factory import ChartFactory
from .chart.registry import ChartRegistry
from .dashboard import Dashboard
from .data import DataService
from .filters.factory import FilterFactory
from .repository import DashboardRepository
from .types.chart import AvailableChartTypes
from .types.common import CollectionName

logger: Logger = logging.getLogger(__name__)


class DashboardManager:
    """Central manager for dashboards, charts, and filters."""

    def __init__(self, data_service: DataService) -> None:
        self.data_service = data_service

        db = data_service.mongo.db
        if db is None:
            error_msg = "MongoDB database is not initialized"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        self.repository = DashboardRepository(db)
        logger.debug("[DashboardManager initialized successfully")

        self.chart_registries: dict[CollectionName, ChartRegistry] = {
            collection_name: ChartRegistry(collection_name=collection_name) for collection_name in CollectionName
        }

        self.filter_factories: dict[CollectionName, FilterFactory] = {
            collection_name: FilterFactory(collection_name=collection_name) for collection_name in CollectionName
        }

    def get_chart_registry(self, collection_name: CollectionName) -> ChartRegistry:
        return self.chart_registries[collection_name]

    def get_filter_factory(self, collection_name: CollectionName) -> FilterFactory:
        return self.filter_factories[collection_name]

    def register_predefined_charts(self) -> None:
        self._register_cc_charts()
        self._register_fips_charts()

    def _register_cc_charts(self) -> None:
        cc_chart_registry = self.chart_registries[CollectionName.CommonCriteria]

        category_distribution_config = ChartConfig(
            chart_id=uuid4(),
            name="cc-category-distribution",
            title="Category Distribution",
            chart_type=AvailableChartTypes.PIE,
            collection_name=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="category", label="Category"),
            y_axis=None,
            show_legend=True,
            show_grid=False,
        )

        certs_per_year_config = ChartConfig(
            chart_id=uuid4(),
            name="cc-certs-per-year",
            title="Certificates by Category and Year",
            chart_type=AvailableChartTypes.BAR,
            collection_name=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="year_from", label="Year"),
            y_axis=AxisConfig(field="count", label="Number of Certificates"),
            show_legend=True,
            show_grid=True,
        )

        validity_duration_config = ChartConfig(
            chart_id=uuid4(),
            name="cc-validity-duration",
            title="Certificate Validity Duration",
            chart_type=AvailableChartTypes.BOX,
            collection_name=CollectionName.CommonCriteria,
            x_axis=AxisConfig(field="year_from", label="Year of Certification"),
            y_axis=AxisConfig(field="validity_days", label="Lifetime of certificates (in days)"),
            show_legend=True,
            show_grid=True,
        )

        charts = [
            ChartFactory.create_chart(category_distribution_config),
            ChartFactory.create_chart(certs_per_year_config),
            ChartFactory.create_chart(validity_duration_config),
        ]

        for chart in charts:
            cc_chart_registry.register(chart)

    def _register_fips_charts(self) -> None:
        pass

    def get_dashboard_names(
        self,
        user_id: str,
        collection_name: CollectionName,
    ) -> list[dict[str, str]]:
        """
        Get dashboard names for dropdown population (INIT-1 lazy loading).

        Returns minimal data: dashboard_id, name, is_default flag.
        """
        return self.repository.get_names_by_user(user_id, collection_name)

    def load_dashboard_with_charts(
        self,
        dashboard_id: str,
    ) -> tuple[Dashboard | None, list]:
        """
        Load dashboard and instantiate BaseChart components from stored configs.

        Implements INIT-2 callback reconstruction by using ChartFactory
        to create runtime chart instances from serialized Chart configs.

        :return: Tuple of (Dashboard, list of BaseChart instances)
        """
        dashboard = self.repository.get_by_id(dashboard_id)
        if dashboard is None:
            return None, []

        chart_instances = []
        for chart_config in dashboard.charts:
            try:
                chart_instance = ChartFactory.create_chart(chart_config)
                chart_instances.append(chart_instance)
            except (ValueError, Exception) as e:
                error_chart = ErrorChart(
                    config=chart_config,
                    error_message=str(e),
                )
                chart_instances.append(error_chart)

        return dashboard, chart_instances

    def load_default_dashboard(
        self,
        user_id: str,
        collection_name: CollectionName,
    ) -> tuple[Dashboard | None, list]:
        """
        Load user's default dashboard for INIT-3 first access.

        :return: Tuple of (Dashboard, list of BaseChart instances) or (None, [])
        """
        dashboard = self.repository.get_default(user_id, collection_name)
        if dashboard is None:
            return None, []

        chart_instances = []
        for chart_config in dashboard.charts:
            try:
                chart_instance = ChartFactory.create_chart(chart_config)
                chart_instances.append(chart_instance)
            except (ValueError, Exception) as e:
                error_chart = ErrorChart(
                    config=chart_config,
                    error_message=str(e),
                )
                chart_instances.append(error_chart)

        return dashboard, chart_instances

    def get_predefined_chart_configs(self, collection_name: CollectionName) -> list[ChartConfig]:
        """
        Get predefined chart configurations for 'Load Predefined' option.

        Returns Chart dataclass instances (not BaseChart) for serialization.
        """
        registry = self.chart_registries.get(collection_name)
        if not registry:
            return []

        return [chart.config for chart in registry]

    def create_dashboard(
        self,
        collection_name: CollectionName,
        user_id: str,
        name: str = "New dashboard",
        description: Optional[str] = None,
        is_default: bool = False,
    ) -> Dashboard:
        return Dashboard(
            user_id=user_id,
            collection_name=collection_name,
            name=name,
            description=description,
            is_default=is_default,
        )

    def save_dashboard(self, dashboard: Dashboard) -> str:
        return self.repository.save(dashboard)

    def get_dashboard(self, dashboard_id: str) -> Optional[Dashboard]:
        return self.repository.get_by_id(dashboard_id)

    def get_user_dashboards(
        self,
        user_id: str,
        collection_name: Optional[CollectionName] = None,
    ) -> list[Dashboard]:
        return self.repository.get_by_user(user_id, collection_name)

    def get_default_dashboard(self, user_id: str, collection_name: CollectionName) -> Optional[Dashboard]:
        return self.repository.get_default(user_id, collection_name)

    def delete_dashboard(self, dashboard_id: str, user_id: str) -> bool:
        return self.repository.delete(dashboard_id, user_id)

    def count_user_dashboards(self, user_id: str, collection_name: Optional[CollectionName] = None) -> int:
        return self.repository.count_by_user(user_id, collection_name)
