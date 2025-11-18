"""A chart showing the distribution of CC certificate categories."""

import plotly.graph_objects as go
from dash import Dash, dcc, html
from dash.dependencies import Input, Output

from sec_certs_page.dashboard.data import DataService

from ..base import BaseChart


class CCCategoryDistribution(BaseChart):
    """A chart showing the distribution of CC certificate categories."""

    def __init__(self, graph_id: str, data_service: DataService):
        super().__init__(graph_id, data_service, chart_type="pie", available_chart_types=["pie", "bar"])

    @property
    def title(self) -> str:
        return "Category Distribution"

    def render(self) -> html.Div:
        """Renders the chart and its associated dropdown filter."""
        return html.Div(
            [
                *self._render_header(),
                dcc.Graph(id=self.id),
            ]
        )

    def register_callback(self, app: Dash) -> None:
        """Registers the callback to update the chart."""
        outputs = Output(self.id, "figure")

        inputs = [Input("cc-filter-store", "data")]

        if len(self.available_chart_types) > 1:
            inputs.append(Input(self.chart_type_selector_id, "value"))

        @app.callback(outputs, inputs, prevent_initial_call=False)
        def update_chart(*args) -> go.Figure:
            """Fetches data and creates the chart figure."""
            try:
                df = self.data_service.get_cc_dataframe()
                if df.empty:
                    return go.Figure().add_annotation(
                        text="No data available", xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False
                    )

                filter_data = args[0] if args and isinstance(args[0], dict) else {}

                chart_type = self.chart_type  # default
                if len(args) > 1 and args[1]:
                    chart_type = args[1]

                # Apply category filter if available
                category_filter_key = "category-filter"  # Standard filter ID from CCFilterRegistry
                selected_categories = filter_data.get(category_filter_key)
                if selected_categories and isinstance(selected_categories, list) and len(selected_categories) > 0:
                    df = df[df["category"].isin(selected_categories)]

                category_counts = df["category"].value_counts()
                fig = go.Figure()

                if chart_type == "pie":
                    fig.add_trace(go.Pie(labels=category_counts.index, values=category_counts.values, hole=0.3))
                elif chart_type == "bar":
                    fig.add_trace(
                        go.Bar(
                            x=category_counts.index, y=category_counts.values, marker=dict(color=self.color_palette[0])
                        )
                    )

                fig.update_layout(
                    title=f"Number of issued certificates by category ({chart_type.title()} Chart)",
                    margin={"t": 80, "l": 40, "r": 40, "b": 40},
                    height=700,
                )
                return fig

            except Exception as e:
                return go.Figure().add_annotation(
                    text=f"Error: {str(e)}", xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False
                )
