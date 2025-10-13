"""Dynamic filter factory for generating filters based on dataset structure."""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Union

import pandas as pd
from dash import dcc, html
from dash.development.base_component import Component

from ..data import DataService
from .base import BaseFilter


class FilterType(Enum):
    """Enum defining the types of filters that can be generated."""

    DROPDOWN = "dropdown"
    TEXT_SEARCH = "text_search"
    RANGE_SLIDER = "range_slider"
    DATE_RANGE = "date_range"
    SKIP = "skip"


@dataclass
class ColumnMetadata:
    """Metadata about a dataset column for filter generation."""

    name: str
    dtype: str
    filter_type: FilterType
    unique_count: int
    null_count: int
    sample_values: Optional[List[Any]] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None


class FilterTypeDetector:
    """Detects appropriate filter types based on column data."""

    CATEGORICAL_THRESHOLD = 50  # Max unique values for dropdown

    @classmethod
    def detect_filter_type(cls, column: pd.Series, column_name: str) -> ColumnMetadata:
        """
        Analyzes a pandas Series and determines the appropriate filter type.

        :param column: The pandas Series to analyze
        :param column_name: Name of the column
        :return: ColumnMetadata with filter type and relevant information
        """
        # Get basic statistics
        non_null_data = column.dropna()
        null_count = column.isnull().sum()

        if non_null_data.empty:
            return ColumnMetadata(
                name=column_name,
                dtype=str(column.dtype),
                filter_type=FilterType.SKIP,
                unique_count=0,
                null_count=null_count,
            )

        # Get a sample value to check type
        sample_val = non_null_data.iloc[0]

        # Skip complex types (dict, list, etc.)
        if isinstance(sample_val, (dict, list)):
            return ColumnMetadata(
                name=column_name,
                dtype=str(column.dtype),
                filter_type=FilterType.SKIP,
                unique_count=0,
                null_count=null_count,
            )

        # Determine filter type based on data type and characteristics
        unique_count = len(non_null_data.unique())

        if column.dtype in ["int64", "float64"]:
            # Numeric data - use range slider
            return ColumnMetadata(
                name=column_name,
                dtype=str(column.dtype),
                filter_type=FilterType.RANGE_SLIDER,
                unique_count=unique_count,
                null_count=null_count,
                min_value=float(column.min()),
                max_value=float(column.max()),
            )
        elif "datetime" in str(column.dtype):
            # Date/datetime data - use date range picker
            return ColumnMetadata(
                name=column_name,
                dtype=str(column.dtype),
                filter_type=FilterType.DATE_RANGE,
                unique_count=unique_count,
                null_count=null_count,
                min_value=column.min(),
                max_value=column.max(),
            )
        elif column.dtype == "object":
            # String/object data - dropdown for categorical, text search for high cardinality
            if unique_count <= cls.CATEGORICAL_THRESHOLD:
                sample_values = list(non_null_data.unique())
                return ColumnMetadata(
                    name=column_name,
                    dtype=str(column.dtype),
                    filter_type=FilterType.DROPDOWN,
                    unique_count=unique_count,
                    null_count=null_count,
                    sample_values=sample_values,
                )
            else:
                return ColumnMetadata(
                    name=column_name,
                    dtype=str(column.dtype),
                    filter_type=FilterType.TEXT_SEARCH,
                    unique_count=unique_count,
                    null_count=null_count,
                )
        else:
            # Unknown type - skip
            return ColumnMetadata(
                name=column_name,
                dtype=str(column.dtype),
                filter_type=FilterType.SKIP,
                unique_count=unique_count,
                null_count=null_count,
            )


class DynamicDropdownFilter(BaseFilter):
    """Dynamic dropdown filter for categorical data."""

    def __init__(
        self,
        filter_id: str,
        column_metadata: ColumnMetadata,
        label: str | None = None,
        data_service: Optional[DataService] = None,
    ):
        super().__init__(filter_id)
        self.metadata = column_metadata
        self.label = label or f"Filter by {column_metadata.name.replace('_', ' ').title()}:"
        self.data_service = data_service
        self._populated = False

    def _ensure_populated(self, dataset_type: str = "cc"):
        """Ensure metadata is populated with actual data."""
        if not self._populated and self.data_service and not self.metadata.sample_values:
            # Get actual data to populate options
            if dataset_type.lower() == "cc":
                df = self.data_service.get_cc_dataframe()
            elif dataset_type.lower() == "fips":
                df = self.data_service.get_fips_dataframe()
            else:
                return

            if not df.empty and self.metadata.name in df.columns:
                column = df[self.metadata.name]
                non_null_data = column.dropna()
                if len(non_null_data.unique()) <= 50:  # Only if reasonable number of options
                    self.metadata.sample_values = list(non_null_data.unique())

            self._populated = True

    def render(self, dataset_type: str = "cc") -> Component:
        """Renders the dropdown filter component."""
        self._ensure_populated(dataset_type)

        options = []
        if self.metadata.sample_values:
            options = [{"label": str(val), "value": val} for val in self.metadata.sample_values]

        return html.Div(
            [
                html.Label(self.label),
                dcc.Dropdown(
                    id=self.id,
                    options=options,  # type: ignore[arg-type]
                    value=[],
                    multi=True,
                    placeholder=f"Select {self.metadata.name}...",
                ),
            ]
        )


class DynamicTextSearchFilter(BaseFilter):
    """Dynamic text search filter for high-cardinality text data."""

    def __init__(self, filter_id: str, column_metadata: ColumnMetadata, label: str | None = None):
        super().__init__(filter_id)
        self.metadata = column_metadata
        self.label = label or f"Search {column_metadata.name.replace('_', ' ').title()}:"

    def render(self, dataset_type: str = "cc") -> Component:
        """Renders the text search filter component."""
        return html.Div(
            [
                html.Label(self.label),
                dcc.Input(
                    id=self.id,
                    type="text",
                    placeholder=f"Search {self.metadata.name}...",
                    debounce=True,
                    style={"width": "100%"},
                ),
            ]
        )


class DynamicRangeSliderFilter(BaseFilter):
    """Dynamic range slider filter for numeric data."""

    def __init__(self, filter_id: str, column_metadata: ColumnMetadata, label: str | None = None):
        super().__init__(filter_id)
        self.metadata = column_metadata
        self.label = label or f"Filter {column_metadata.name.replace('_', ' ').title()} Range:"

    def render(self, dataset_type: str = "cc") -> Component:
        """Renders the range slider filter component."""
        min_val = self.metadata.min_value or 0.0
        max_val = self.metadata.max_value or 100.0

        return html.Div(
            [
                html.Label(self.label),
                dcc.RangeSlider(
                    id=self.id,
                    min=min_val,
                    max=max_val,
                    value=[min_val, max_val],  # type: ignore[list-item]
                    marks={min_val: str(min_val), max_val: str(max_val)},  # type: ignore[dict-item]
                    tooltip={"placement": "bottom", "always_visible": True},
                ),
            ]
        )


class FilterFactory:
    """Factory class for generating filters dynamically based on dataset structure."""

    def __init__(self, data_service: DataService):
        self.data_service = data_service
        self._metadata_cache: Dict[str, List[ColumnMetadata]] = {}

    def analyze_dataset(self, dataset_type: str) -> list[ColumnMetadata]:
        """
        Analyzes a dataset and returns metadata for all columns.
        Results are cached to avoid repeated database queries.

        :param dataset_type: Type of dataset ('cc' or 'fips')
        :return: List of ColumnMetadata objects
        """
        # Check cache first
        if dataset_type in self._metadata_cache:
            return self._metadata_cache[dataset_type]

        if dataset_type.lower() == "cc":
            df = self.data_service.get_cc_dataframe()
        elif dataset_type.lower() == "fips":
            df = self.data_service.get_fips_dataframe()
        else:
            raise ValueError(f"Unknown dataset type: {dataset_type}")

        if df.empty:
            return []

        metadata_list = []
        for column_name in df.columns:
            metadata = FilterTypeDetector.detect_filter_type(df[column_name], column_name)
            metadata_list.append(metadata)

        # Cache the results
        self._metadata_cache[dataset_type] = metadata_list
        return metadata_list

    def get_priority_filters_for_dataset(self, dataset_type: str) -> list[ColumnMetadata]:
        """
        Analyzes dataset and returns metadata for priority columns only.
        This is called when dashboard pages are visited, not during initialization.

        :param dataset_type: Type of dataset ('cc' or 'fips')
        :return: List of ColumnMetadata objects for priority filters
        """
        # Get full analysis but filter to priority columns only
        all_metadata = self.analyze_dataset(dataset_type)

        if dataset_type.lower() == "cc":
            priority_columns = ["category", "status", "scheme", "manufacturer"]
        elif dataset_type.lower() == "fips":
            priority_columns = ["status"]
        else:
            raise ValueError(f"Unknown dataset type: {dataset_type}")

        # Return only metadata for priority columns
        return [meta for meta in all_metadata if meta.name in priority_columns]

    def create_filter(self, column_metadata: ColumnMetadata, filter_id: str | None = None) -> BaseFilter | None:
        """
        Creates a filter instance based on column metadata.

        :param column_metadata: Metadata about the column
        :param filter_id: Optional custom filter ID
        :return: Filter instance or None if not filterable
        """
        if column_metadata.filter_type == FilterType.SKIP:
            return None

        filter_id = filter_id or f"filter-{column_metadata.name}"

        if column_metadata.filter_type == FilterType.DROPDOWN:
            return DynamicDropdownFilter(filter_id, column_metadata, data_service=self.data_service)
        elif column_metadata.filter_type == FilterType.TEXT_SEARCH:
            return DynamicTextSearchFilter(filter_id, column_metadata)
        elif column_metadata.filter_type == FilterType.RANGE_SLIDER:
            return DynamicRangeSliderFilter(filter_id, column_metadata)
        elif column_metadata.filter_type == FilterType.DATE_RANGE:
            # TODO: Implement date range filter
            return None

        return None

    def create_filters_for_dataset(self, dataset_type: str) -> list[BaseFilter]:
        """
        Creates all appropriate filters for a given dataset.

        :param dataset_type: Type of dataset ('cc' or 'fips')
        :return: List of filter instances
        """
        metadata_list = self.analyze_dataset(dataset_type)
        filters = []

        for metadata in metadata_list:
            filter_instance = self.create_filter(metadata)
            if filter_instance:
                filters.append(filter_instance)

        return filters

    def get_filterable_columns(self, dataset_type: str) -> list[ColumnMetadata]:
        """
        Returns metadata for columns that can be filtered.

        :param dataset_type: Type of dataset ('cc' or 'fips')
        :return: List of filterable ColumnMetadata objects
        """
        all_metadata = self.analyze_dataset(dataset_type)
        return [meta for meta in all_metadata if meta.filter_type != FilterType.SKIP]
