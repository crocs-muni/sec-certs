"""Implements the Registry Pattern for managing dashboard graphs."""

from typing import Dict, Iterator

from sec_certs_page.dashboard.graphs.base import BaseGraph


class GraphRegistry:
    """A registry for storing and managing graph components.

    This class follows the Singleton and Registry design patterns to provide a
    central point of access for all graph instances within the application.
    """

    def __init__(self) -> None:
        self._graphs: Dict[str, BaseGraph] = {}

    def register(self, graph: BaseGraph) -> None:
        """Registers a new graph instance.

        Args:
            graph: An instance of a class derived from BaseGraph.

        Raises:
            ValueError: If a graph with the same ID is already registered.
        """
        if graph.id in self._graphs:
            raise ValueError(f"Graph with ID '{graph.id}' is already registered.")
        self._graphs[graph.id] = graph

    def __getitem__(self, graph_id: str) -> BaseGraph:
        """Retrieves a graph instance by its ID.

        Args:
            graph_id: The unique identifier of the graph.

        Returns:
            The graph instance.
        """
        return self._graphs[graph_id]

    def __iter__(self) -> Iterator[BaseGraph]:
        """Allows iteration over the registered graphs."""
        return iter(self._graphs.values())
