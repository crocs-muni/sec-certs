# sec_certs_page/dashboard/graphs/cc_validity_duration.py
"""A box plot showing the validity duration of CC certificates over the years."""
# NEW FILE
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from dash import Dash, dcc, html
from dash.dependencies import Input, Output

from ...data import DataService
from ..base import BaseChart


class CCValidityDuration(BaseChart):
    """A box plot showing the variance of certificate validity duration per year."""

    def __init__(self, graph_id: str, data_service: DataService):
        super().__init__(graph_id, data_service, available_chart_types=["box"])

    @property
    def title(self) -> str:
        return "Certificate Validity Duration"

    def render(self) -> html.Div:
        """Renders the box plot and its associated controls."""
        return html.Div(
            [
                *self._render_header(),
                dcc.Graph(id=self.id),
            ]
        )

    def register_callback(self, app: Dash) -> None:
        """Registers the callback to update the box plot."""

        @app.callback(
            Output(self.id, "figure"),
            Input("cc-filter-store", "data"),
        )
        def update_boxplot(filter_data: dict) -> go.Figure:
            """Fetches data and creates the box plot figure."""
            df = self.data_service.get_cc_dataframe()
            if df.empty:
                return go.Figure()

            # Apply filters from the central store
            selected_categories = filter_data.get("cc-category-filter")
            if selected_categories:
                df = df[df["category"].isin(selected_categories)]

            df["not_valid_before"] = pd.to_datetime(df["not_valid_before"], unit="ms", errors="coerce")
            df["not_valid_after"] = pd.to_datetime(df["not_valid_after"], unit="ms", errors="coerce")
            df.dropna(subset=["not_valid_before", "not_valid_after"], inplace=True)

            df["validity_days"] = (df["not_valid_after"] - df["not_valid_before"]).dt.days
            df = df[df["validity_days"] >= 0]  # Ensure non-negative validity

            df["year_from"] = df["not_valid_before"].dt.year
            sorted_years = sorted(df["year_from"].unique())

            fig = px.box(
                df,
                x="year_from",
                y="validity_days",
                title="Variance of Certificate Validity Duration",
                labels={
                    "validity_days": "Lifetime of certificates (in days)",
                    "year_from": "Year of Certification",
                },
                category_orders={"year_from": sorted_years},
                color_discrete_sequence=self.color_palette,
            )
            fig.update_layout(height=600)
            return fig
