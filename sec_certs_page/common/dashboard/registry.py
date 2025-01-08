# sec_certs_page/common/dashboard/registry.py
from collections.abc import Mapping
from typing import Dict, Generic, Type, TypeVar

from sec_certs_page.common.dashboard.types import BaseDashboardConfig

from .base import BaseDashboard

T_Dashboard = TypeVar("T_Dashboard", bound=BaseDashboard)
T_Config = TypeVar("T_Config", bound=BaseDashboardConfig)


class DashboardRegistry(Generic[T_Dashboard, T_Config]):
    """
    A generic registry for managing dashboard instances.

    Type Parameters:
        T_Dashboard: Type of dashboard, must be a subclass of BaseDashboard
        T_Config: Type of configuration, must be a Mapping
    """

    _instance: "DashboardRegistry[T_Dashboard, T_Config] | None" = None
    _dashboards: Dict[str, T_Dashboard] = {}
    _dashboard_types: Dict[str, Type[T_Dashboard]] = {}

    def __new__(cls) -> "DashboardRegistry[T_Dashboard, T_Config]":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def register_dashboard_type(self, type_id: str, dashboard_class: Type[T_Dashboard]) -> None:
        """
        Register a dashboard type that can be instantiated later.

        Args:
            type_id: Unique identifier for the dashboard type
            dashboard_class: The dashboard class to register
        """
        if not issubclass(dashboard_class, BaseDashboard):
            raise TypeError(f"Dashboard class must inherit from BaseDashboard, got {dashboard_class}")
        self._dashboard_types[type_id] = dashboard_class

    def create_dashboard(self, type_id: str, config: T_Config) -> T_Dashboard:
        """
        Create a new dashboard instance of the specified type.

        Args:
            type_id: The type of dashboard to create
            config: Configuration for the dashboard

        Returns:
            A new dashboard instance

        Raises:
            KeyError: If the dashboard type is not registered
        """
        if type_id not in self._dashboard_types:
            raise KeyError(f"Dashboard type '{type_id}' not registered")

        dashboard_class = self._dashboard_types[type_id]
        dashboard = dashboard_class(config)
        self._dashboards[config["id"]] = dashboard
        return dashboard

    def get_dashboard(self, dashboard_id: str) -> T_Dashboard | None:
        """
        Retrieve a dashboard instance by ID.

        Args:
            dashboard_id: The ID of the dashboard to retrieve

        Returns:
            The dashboard instance or None if not found
        """
        return self._dashboards.get(dashboard_id)

    def get_dashboards(self) -> Dict[str, T_Dashboard]:
        """
        Get all registered dashboard instances.

        Returns:
            A dictionary of dashboard instances keyed by their IDs
        """
        return self._dashboards.copy()
