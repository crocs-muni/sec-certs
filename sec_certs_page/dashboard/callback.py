"""Callback management for Dash applications provides class with methods to register and manage callbacks.

Use callback manager to register callbacks for existing charts and components stored in ChartRegistry and ComponentRegistry.
"""

from dash import Dash

from .charts.registry import ChartRegistry


class CallbackManager:
    """
    Manages the registration of all Dash callbacks for the application.

    This class iterates through the registered components (e.g., charts) and
    delegates the callback registration logic to each component itself.
    """

    def __init__(self, cc_chart_registry: ChartRegistry):
        """
        :param cc_chart_registry: The registry containing CC dashboard charts.
        :type cc_chart_registry: ChartRegistry
        """
        self.cc_chart_registry = cc_chart_registry

    def register_callbacks(self, app: Dash) -> None:
        """
        Registers all callbacks with the Dash application instance.

        It iterates through every chart in the registry and calls its
        `register_callback` method.

        :param app: The main Dash application instance to which callbacks
            will be registered.
        :type app: Dash
        """
        for graph in self.cc_chart_registry:
            graph.register_callback(app)
