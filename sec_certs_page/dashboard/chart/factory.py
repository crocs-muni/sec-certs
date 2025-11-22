import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from sec_certs_page.dashboard.chart.base import BaseChart
from sec_certs_page.dashboard.chart.chart import Chart
from sec_certs_page.dashboard.chart.graphs import (
    BarChartComponent,
    BoxChartComponent,
    HistogramChartComponent,
    LineChartComponent,
    PieChartComponent,
    ScatterChartComponent,
)
from sec_certs_page.dashboard.data import DataService
from sec_certs_page.dashboard.types.chart import AvailableChartTypes
from sec_certs_page.dashboard.types.filter import AggregationType


class ChartFactory:
    """Factory that creates BaseChart instances from Chart configurations."""

    _chart_classes: dict[AvailableChartTypes, type[BaseChart]] = {
        AvailableChartTypes.BAR: BarChartComponent,
        AvailableChartTypes.LINE: LineChartComponent,
        AvailableChartTypes.PIE: PieChartComponent,
        AvailableChartTypes.SCATTER: ScatterChartComponent,
        AvailableChartTypes.BOX: BoxChartComponent,
        AvailableChartTypes.HISTOGRAM: HistogramChartComponent,
    }

    @classmethod
    def create_chart(cls, config: Chart, data_service: DataService) -> BaseChart:
        """Create a BaseChart instance from a Chart configuration."""
        chart_class = cls._chart_classes.get(config.chart_type)
        if not chart_class:
            raise ValueError(f"Unknown chart type: {config.chart_type}")

        return chart_class(
            graph_id=str(config.chart_id),
            data_service=data_service,
            chart_type=config.chart_type.value,
            config=config,
        )

    @classmethod
    def create_figure(cls, config: Chart, df: pd.DataFrame) -> go.Figure:
        """Create Plotly figure from config and data."""
        if df.empty:
            return cls._empty_figure("No data available")

        x_field = config.x_axis.field
        y_field = config.y_axis.field if config.y_axis else None
        aggregation = config.y_axis.aggregation if config.y_axis else None

        try:
            agg_df = cls._aggregate_data(df, x_field, y_field, aggregation)
            fig = cls._create_chart_by_type(config, agg_df, x_field, y_field or "count")
            fig.update_layout(
                showlegend=config.show_legend,
                template="plotly_white",
                margin=dict(l=40, r=40, t=60, b=40),
            )
            return fig
        except Exception as e:
            return cls._empty_figure(f"Error: {str(e)}")

    @classmethod
    def _aggregate_data(
        cls,
        df: pd.DataFrame,
        x_field: str,
        y_field: str | None,
        aggregation: AggregationType | None,
    ) -> pd.DataFrame:
        """Apply aggregation to data."""
        if x_field not in df.columns:
            raise ValueError(f"Field '{x_field}' not found in data")

        if y_field and y_field in df.columns:
            if aggregation == AggregationType.SUM:
                return df.groupby(x_field)[y_field].sum().reset_index()
            elif aggregation == AggregationType.AVG:
                return df.groupby(x_field)[y_field].mean().reset_index()
            elif aggregation == AggregationType.MIN:
                return df.groupby(x_field)[y_field].min().reset_index()
            elif aggregation == AggregationType.MAX:
                return df.groupby(x_field)[y_field].max().reset_index()
            else:
                return df.groupby(x_field).size().reset_index(name="count")
        else:
            return df.groupby(x_field).size().reset_index(name="count")

    @classmethod
    def _create_chart_by_type(
        cls,
        config: Chart,
        df: pd.DataFrame,
        x_field: str,
        y_field: str,
    ) -> go.Figure:
        """Create chart based on chart type."""
        if config.chart_type == AvailableChartTypes.BAR:
            return px.bar(df, x=x_field, y=y_field, title=config.title)
        elif config.chart_type == AvailableChartTypes.LINE:
            return px.line(df, x=x_field, y=y_field, title=config.title, markers=True)
        elif config.chart_type == AvailableChartTypes.PIE:
            return px.pie(df, names=x_field, values=y_field, title=config.title)
        elif config.chart_type == AvailableChartTypes.SCATTER:
            return px.scatter(df, x=x_field, y=y_field, title=config.title)
        elif config.chart_type == AvailableChartTypes.BOX:
            return px.box(df, x=x_field, y=y_field, title=config.title)
        elif config.chart_type == AvailableChartTypes.HISTOGRAM:
            return px.histogram(df, x=x_field, title=config.title)
        else:
            return cls._empty_figure(f"Unsupported chart type: {config.chart_type}")

    @staticmethod
    def _empty_figure(message: str = "No data") -> go.Figure:
        """Create an empty figure with a message."""
        fig = go.Figure()
        fig.add_annotation(
            text=message,
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.5,
            showarrow=False,
            font=dict(size=16, color="gray"),
        )
        fig.update_layout(
            xaxis=dict(visible=False),
            yaxis=dict(visible=False),
        )
        return fig
