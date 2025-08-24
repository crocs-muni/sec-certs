import dash
from dash import dcc, html


class DashboardLayoutManager:
    """Manages the creation and structure of the dashboard's layout."""

    def build_layout(self) -> html.Div:
        """Constructs the main layout of the dashboard.

        This will eventually fetch user configurations and use the
        component registries to build a dynamic layout.
        """
        # For now, placeholder layout
        return html.Div(
            [
                html.H1("Multi-page app with Dash Pages"),
                html.Div(
                    [
                        html.Div(dcc.Link(f"{page['name']} - {page['path']}", href=page["relative_path"]))
                        for page in dash.page_registry.values()
                    ]
                ),
                dash.page_container,
            ]
        )
