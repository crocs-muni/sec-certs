from typing import Optional
from uuid import uuid4

from .chart.cc import CCCategoryDistribution, CCCertsPerYear, CCValidityDuration
from .chart.chart import AxisConfig, Chart
from .chart.registry import ChartRegistry
from .dashboard import Dashboard
from .data import DataService
from .filters.component_factory import DashFilterFactory
from .repository import DashboardRepository
from .types.chart import AvailableChartTypes
from .types.common import CollectionName


class DashboardManager:
    """Central manager for dashboards, charts, and filters."""

    def __init__(self, data_service: DataService) -> None:
        self.data_service = data_service

        db = data_service.mongo.db
        if db is None:
            raise RuntimeError("MongoDB database is not initialized")
        self.repository = DashboardRepository(db)

        self.chart_registries: dict[CollectionName, ChartRegistry] = {
            dataset_type: ChartRegistry(dataset_type=dataset_type) for dataset_type in CollectionName
        }

        self.filter_factories: dict[CollectionName, DashFilterFactory] = {
            dataset_type: DashFilterFactory(dataset_type=dataset_type) for dataset_type in CollectionName
        }

    def get_chart_registry(self, dataset_type: CollectionName) -> ChartRegistry:
        """Get chart registry for a dataset type."""
        return self.chart_registries[dataset_type]

    def get_filter_factory(self, dataset_type: CollectionName) -> DashFilterFactory:
        """Get filter factory for a dataset type."""
        return self.filter_factories[dataset_type]

    def register_predefined_charts(self) -> None:
        """Register all predefined charts with their registries."""
        self._register_cc_charts()
        self._register_fips_charts()

    def _register_cc_charts(self) -> None:
        """Register predefined CC charts."""
        cc_chart_registry = self.chart_registries[CollectionName.CommonCriteria]

        category_distribution_config = Chart(
            chart_id=uuid4(),
            name="cc-category-distribution",
            title="Category Distribution",
            chart_type=AvailableChartTypes.PIE,
            x_axis=AxisConfig(field="category", label="Category"),
            y_axis=None,
            show_legend=True,
            show_grid=False,
        )

        certs_per_year_config = Chart(
            chart_id=uuid4(),
            name="cc-certs-per-year",
            title="Certificates by Category and Year",
            chart_type=AvailableChartTypes.BAR,
            x_axis=AxisConfig(field="year_from", label="Year"),
            y_axis=AxisConfig(field="count", label="Number of Certificates"),
            show_legend=True,
            show_grid=True,
        )

        validity_duration_config = Chart(
            chart_id=uuid4(),
            name="cc-validity-duration",
            title="Certificate Validity Duration",
            chart_type=AvailableChartTypes.BOX,
            x_axis=AxisConfig(field="year_from", label="Year of Certification"),
            y_axis=AxisConfig(field="validity_days", label="Lifetime of certificates (in days)"),
            show_legend=True,
            show_grid=True,
        )

        charts = [
            CCCategoryDistribution(
                graph_id="cc-category-distribution",
                data_service=self.data_service,
                config=category_distribution_config,
            ),
            CCCertsPerYear(
                graph_id="cc-certs-per-year",
                data_service=self.data_service,
                config=certs_per_year_config,
            ),
            CCValidityDuration(
                graph_id="cc-validity-duration",
                data_service=self.data_service,
                config=validity_duration_config,
            ),
        ]

        for chart in charts:
            cc_chart_registry.register(chart)

    def _register_fips_charts(self) -> None:
        """Register predefined FIPS charts."""
        pass

    def create_dashboard(
        self,
        dataset_type: CollectionName,
        user_id: str,
        name: str = "New dashboard",
        description: Optional[str] = None,
        is_default: bool = False,
    ) -> Dashboard:
        """Create a new dashboard instance."""
        return Dashboard(
            user_id=user_id,
            collection_name=dataset_type,
            name=name,
            description=description,
            is_default=is_default,
        )

    def save_dashboard(self, dashboard: Dashboard) -> str:
        """Save dashboard to MongoDB."""
        return self.repository.save(dashboard)

    def get_dashboard(self, dashboard_id: str) -> Optional[Dashboard]:
        """Retrieve dashboard from MongoDB."""
        return self.repository.get_by_id(dashboard_id)

    def get_user_dashboards(
        self,
        user_id: str,
        dataset_type: Optional[CollectionName] = None,
    ) -> list[Dashboard]:
        """Get all dashboards for a user."""
        return self.repository.get_by_user(user_id, dataset_type)

    def get_default_dashboard(self, user_id: str, dataset_type: CollectionName) -> Optional[Dashboard]:
        """Get user's default dashboard for a dataset type."""
        return self.repository.get_default(user_id, dataset_type)

    def delete_dashboard(self, dashboard_id: str, user_id: str) -> bool:
        """Delete dashboard from MongoDB."""
        return self.repository.delete(dashboard_id, user_id)

    def count_user_dashboards(self, user_id: str, dataset_type: Optional[CollectionName] = None) -> int:
        """Count dashboards for a user."""
        return self.repository.count_by_user(user_id, dataset_type)
