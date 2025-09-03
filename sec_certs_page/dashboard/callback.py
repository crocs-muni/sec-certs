"""Callback management for Dash applications provides class with methods to register and manage callbacks.

Use callback manager to register callbacks for existing graphs and components stored in GraphRegistry and ComponentRegistry.
"""

from dash import Dash

from .graphs.registry import GraphRegistry


class CallbackManager:
    """
    Manages the registration of all Dash callbacks for the application.

    This class iterates through the registered components (e.g., graphs) and
    delegates the callback registration logic to each component itself.
    """

    def __init__(self, cc_graph_registry: GraphRegistry):
        """
        :param cc_graph_registry: The registry containing CC dashboard graphs.
        :type cc_graph_registry: GraphRegistry
        """
        self.cc_graph_registry = cc_graph_registry

    def register_callbacks(self, app: Dash) -> None:
        """
        Registers all callbacks with the Dash application instance.

        It iterates through every graph in the registry and calls its
        `register_callback` method.

        :param app: The main Dash application instance to which callbacks
            will be registered.
        :type app: Dash
        """
        for graph in self.cc_graph_registry:
            graph.register_callback(app)
