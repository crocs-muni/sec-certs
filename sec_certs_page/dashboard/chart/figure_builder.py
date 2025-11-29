"""Figure creation utilities for chart rendering.

This module provides FigureBuilder for creating Plotly figures from
Chart configurations and DataFrames. It's separated from ChartFactory
to avoid circular imports with graph components.
"""

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from ..types.chart import AvailableChartTypes
from ..types.filter import AggregationType
from .chart import Chart


class FigureBuilder:
    """Builder for creating Plotly figures from chart configurations."""

    @classmethod
    def create_figure(cls, config: Chart, df: pd.DataFrame) -> go.Figure:
        """Create Plotly figure from config and data.

        :param config: Chart configuration with axes and type info
        :param df: DataFrame with data to plot
        :return: Plotly Figure object
        """
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
                margin=dict(l=40, r=40, t=40, b=40),
                height=450,
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
            return px.bar(df, x=x_field, y=y_field)
        elif config.chart_type == AvailableChartTypes.LINE:
            return px.line(df, x=x_field, y=y_field, markers=True)
        elif config.chart_type == AvailableChartTypes.PIE:
            return px.pie(df, names=x_field, values=y_field)
        elif config.chart_type == AvailableChartTypes.SCATTER:
            return px.scatter(df, x=x_field, y=y_field)
        elif config.chart_type == AvailableChartTypes.BOX:
            return px.box(df, x=x_field, y=y_field)
        elif config.chart_type == AvailableChartTypes.HISTOGRAM:
            return px.histogram(df, x=x_field)
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
