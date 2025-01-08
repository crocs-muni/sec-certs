# sec_certs_page/cc/charts.py
import plotly.express as px
from dash import dcc

from ..common.dashboard.base import BaseChart


class CCPieChart(BaseChart):
    """Pie chart for CC data."""

    def get_layout(self):
        return dcc.Graph(id=self.id, figure=self.figure)

    def update(self, data):
        self.figure = px.pie(
            data["categories"], title=self.title, names="name", values="value", labels={"value": "count"}
        )


class CCBarChart(BaseChart):
    """Bar chart for CC data."""

    def get_layout(self):
        return dcc.Graph(id=self.id, figure=self.figure)

    def update(self, data):
        self.figure = px.bar(data["categories"], title=self.title, x="name", y="value")
