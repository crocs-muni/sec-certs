"""Figure creation utilities for chart rendering.

This module provides FigureBuilder for creating Plotly figures from
Chart configurations and DataFrames. It's separated from ChartFactory
to avoid circular imports with graph components.
"""

import logging

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from ..types.chart import AvailableChartTypes
from ..types.filter import AggregationType
from .chart import ChartConfig

logger = logging.getLogger(__name__)


class FigureBuilder:
    """Builder for creating Plotly figures from chart configurations."""

    @classmethod
    def create_figure(cls, config: ChartConfig, df: pd.DataFrame) -> go.Figure:
        """Create Plotly figure from config and raw data.

        This method aggregates raw data using pandas before creating the chart.
        Use create_figure_from_aggregated() when data is already aggregated
        (e.g., from MongoDB aggregation pipeline).

        :param config: Chart configuration with axes and type info
        :param df: DataFrame with raw data to aggregate and plot
        :return: Plotly Figure object
        """
        if df.empty:
            return cls._empty_figure("No data available")

        x_field = config.x_axis.field
        y_field = config.y_axis.field if config.y_axis else None
        aggregation = config.y_axis.aggregation if config.y_axis else None
        color_field = config.color_axis.field if config.color_axis else None

        try:
            # Box plots and histograms need raw data distributions, not aggregated summaries
            if config.chart_type in (AvailableChartTypes.BOX, AvailableChartTypes.HISTOGRAM):
                columns = [x_field]
                if y_field:
                    if y_field not in df.columns:
                        error_message = f"Box plot requires y-field '{y_field}' but it's not in the DataFrame columns: {list(df.columns)}"
                        logger.error(error_message)
                        return cls._empty_figure(f"Missing field: {y_field}", is_error=True)
                    columns.append(y_field)
                if color_field and color_field in df.columns:
                    columns.append(color_field)
                agg_df = df[columns]
            else:
                # For other chart types, aggregate the data
                agg_df = cls._aggregate_data(df, x_field, y_field, aggregation, color_field)

            fig = cls._create_chart_by_type(config, agg_df, x_field, y_field or "count", color_field)
            fig.update_layout(
                showlegend=config.show_legend,
                template="plotly_white",
                margin=dict(l=40, r=40, t=40, b=40),
                height=600,
            )
            return fig
        except Exception as e:
            error_message = f"Error creating figure for chart '{config.name}' (type: {config.chart_type})"
            logger.exception(error_message)
            return cls._empty_figure(f"Error: {str(e)}", is_error=True)

    @classmethod
    def create_figure_from_aggregated(cls, config: ChartConfig, df: pd.DataFrame) -> go.Figure:
        """Create Plotly figure from pre-aggregated data.

        This method is used when data has already been aggregated by MongoDB
        aggregation pipeline. It expects the DataFrame to have columns matching
        the x_axis.field and y_axis.label (or 'value' as fallback).

        For charts with color_axis (secondary grouping), the DataFrame should
        have an additional column for the color dimension.

        :param config: Chart configuration with axes and type info
        :param df: DataFrame with pre-aggregated data
        :return: Plotly Figure object
        """
        if df.empty:
            return cls._empty_figure("No data available")

        # Get field names, flattening dots for nested fields (matches query_builder output)
        x_field = config.x_axis.field.replace(".", "_")
        # The pipeline uses y_axis.label as the value column name
        y_field = config.y_axis.label if config.y_axis else "value"

        # Fallback to 'value' if the label column doesn't exist
        if y_field not in df.columns and "value" in df.columns:
            y_field = "value"

        # Get color field if secondary grouping is used (also flatten dots)
        color_field = config.color_axis.field.replace(".", "_") if config.color_axis else None

        if x_field not in df.columns:
            return cls._empty_figure(f"Missing column: {x_field}", is_error=True)
        if y_field not in df.columns:
            return cls._empty_figure(f"Missing column: {y_field}", is_error=True)
        if color_field and color_field not in df.columns:
            return cls._empty_figure(f"Missing color column: {color_field}", is_error=True)

        try:
            fig = cls._create_chart_by_type(config, df, x_field, y_field, color_field)
            fig.update_layout(
                showlegend=config.show_legend,
                template="plotly_white",
                margin=dict(l=40, r=40, t=40, b=40),
                height=600,
            )
            return fig
        except Exception as e:
            error_message = (
                f"Error creating figure from aggregated data for chart '{config.name}' "
                f"(type: {config.chart_type}, x={x_field}, y={y_field})"
            )
            logger.exception(error_message)
            return cls._empty_figure(f"Error: {str(e)}", is_error=True)

    @classmethod
    def _aggregate_data(
        cls,
        df: pd.DataFrame,
        x_field: str,
        y_field: str | None,
        aggregation: AggregationType | None,
        color_field: str | None = None,
    ) -> pd.DataFrame:
        """Apply aggregation to data.

        :param df: DataFrame with raw data
        :param x_field: Field to group by (X-axis)
        :param y_field: Field to aggregate (Y-axis)
        :param aggregation: Aggregation function to apply
        :param color_field: Optional secondary grouping field (for multi-series)
        :return: Aggregated DataFrame
        """
        if x_field not in df.columns:
            raise ValueError(f"Field '{x_field}' not found in data")

        # Determine grouping columns
        group_cols = [x_field]
        if color_field and color_field in df.columns:
            group_cols.append(color_field)

        if y_field and y_field in df.columns:
            if aggregation == AggregationType.SUM:
                return df.groupby(group_cols)[y_field].sum().reset_index()
            elif aggregation == AggregationType.AVG:
                return df.groupby(group_cols)[y_field].mean().reset_index()
            elif aggregation == AggregationType.MIN:
                return df.groupby(group_cols)[y_field].min().reset_index()
            elif aggregation == AggregationType.MAX:
                return df.groupby(group_cols)[y_field].max().reset_index()
            else:
                return df.groupby(group_cols).size().reset_index(name="count")
        else:
            return df.groupby(group_cols).size().reset_index(name="count")

    @classmethod
    def _create_chart_by_type(
        cls,
        config: ChartConfig,
        df: pd.DataFrame,
        x_field: str,
        y_field: str,
        color_field: str | None = None,
    ) -> go.Figure:
        """Create chart based on chart type.

        :param config: Chart configuration
        :param df: DataFrame with data to plot
        :param x_field: Column name for X-axis
        :param y_field: Column name for Y-axis
        :param color_field: Optional column name for color dimension (secondary grouping)
        :return: Plotly Figure object
        """
        # Build labels dict to map field names to user-friendly labels
        labels = {
            x_field: config.x_axis.label,
            y_field: config.y_axis.label if config.y_axis else "Count",
        }
        if color_field and config.color_axis:
            labels[color_field] = config.color_axis.label

        if config.chart_type == AvailableChartTypes.BAR:
            return px.bar(df, x=x_field, y=y_field, color=color_field, barmode="group", labels=labels)
        elif config.chart_type == AvailableChartTypes.STACKED_BAR:
            return px.bar(df, x=x_field, y=y_field, color=color_field, barmode="stack", labels=labels)
        elif config.chart_type == AvailableChartTypes.LINE:
            return px.line(df, x=x_field, y=y_field, color=color_field, markers=True, labels=labels)
        elif config.chart_type == AvailableChartTypes.PIE:
            # Pie charts don't support color dimension in the same way
            return px.pie(df, names=x_field, values=y_field, labels=labels)
        elif config.chart_type == AvailableChartTypes.SCATTER:
            return px.scatter(df, x=x_field, y=y_field, color=color_field, labels=labels)
        elif config.chart_type == AvailableChartTypes.BOX:
            return px.box(df, x=x_field, y=y_field, color=color_field, labels=labels)
        elif config.chart_type == AvailableChartTypes.HISTOGRAM:
            return px.histogram(df, x=x_field, color=color_field, labels=labels)
        else:
            return cls._empty_figure(f"Unsupported chart type: {config.chart_type}")

    @staticmethod
    def _empty_figure(message: str = "No data", is_error: bool = False) -> go.Figure:
        """Create an empty figure with a message.

        :param message: Message to display in the figure
        :param is_error: If True, style the message as an error (red color, icon)
        :return: Empty Plotly figure with the message
        """
        fig = go.Figure()

        # Add error icon if this is an error message
        display_message = f"⚠️ {message}" if is_error else message
        color = "#d9534f" if is_error else "gray"

        fig.add_annotation(
            text=display_message,
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.5,
            showarrow=False,
            font=dict(size=16, color=color),
            align="center",
        )
        fig.update_layout(
            xaxis=dict(visible=False),
            yaxis=dict(visible=False),
            template="plotly_white",
            margin=dict(l=40, r=40, t=40, b=40),
            height=400,
        )
        return fig
