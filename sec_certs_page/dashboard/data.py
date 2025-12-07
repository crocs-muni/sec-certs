"""Data management layer with MongoDB query filtering.

This module provides DataService for querying MongoDB with optional filters.
"""

import logging
from logging import Logger
from typing import Any, TypedDict

import numpy as np
import pandas as pd
from flask_pymongo import PyMongo

from .filters.query_builder import build_query_from_filters
from .types.common import CollectionName

logger: Logger = logging.getLogger(__name__)


class ColumnStats(TypedDict, total=False):
    """Statistics for a single column in the dataset.

    Required fields:
    :param dtype: Data type of the column as string
    :param unique_count: Number of unique non-null values
    :param null_count: Number of null/missing values
    :param total_count: Total number of values (including nulls)

    Optional fields:
    :param min_value: Minimum value (only for numeric columns)
    :param max_value: Maximum value (only for numeric columns)
    :param sample_values: Sample of unique values (only if unique_count <= 50)
    :param error: Error message if column analysis failed
    """

    dtype: str
    unique_count: int
    null_count: int
    total_count: int
    min_value: float
    max_value: float
    sample_values: list[Any]
    error: str


class DataService:
    """Data service for querying MongoDB with optional filtering.

    This service queries MongoDB on every call without in-memory caching.
    Caching should be implemented as a separate layer (e.g., Redis).
    """

    def __init__(self, mongo: PyMongo):
        """Initialize data service.

        :param mongo: Flask-PyMongo instance
        """
        self.mongo = mongo

    def get_cc_dataframe(self, filter_values: dict[str, Any] | None = None) -> pd.DataFrame:
        """Get CC dataset from MongoDB with optional filtering.

        This method always queries MongoDB for fresh data. If you need caching,
        implement it at a higher layer (e.g., Redis, application cache).

        :param filter_values: Optional dictionary mapping filter IDs to values
        :return: CC dataset as DataFrame (filtered or complete)
        """
        query = (
            build_query_from_filters(filter_values, collection_name=CollectionName.CommonCriteria)
            if filter_values
            else {}
        )

        try:
            cursor = self.mongo.db.cc.find(query)  # pyright: ignore[reportOptionalMemberAccess]
            data = list(cursor)

            if not data:
                warning_message = "[GET_CC_DF] CC query returned no results"
                logger.warning(warning_message)
                return pd.DataFrame()

            df = self._prepare_cc_dataframe(data)
            return df

        except Exception as e:
            error_message = "[GET_CC_DF] Error fetching CC data from MongoDB"
            logger.exception(error_message)
            raise e

    def get_fips_dataframe(self, filter_values: dict[str, Any] | None = None) -> pd.DataFrame:
        """Get FIPS dataset from MongoDB with optional filtering.

        This method always queries MongoDB for fresh data. If you need caching,
        implement it at a higher layer (e.g., Redis, application cache).

        :param filter_values: Optional dictionary mapping filter IDs to values
        :return: FIPS dataset as DataFrame (filtered or complete)
        """
        query = build_query_from_filters(filter_values, collection_name=CollectionName.FIPS140) if filter_values else {}

        logger.info(f"[GET_FIPS_DF] Fetching FIPS dataset from MongoDB with query: {query}")

        try:
            cursor = self.mongo.db.fips.find(query)  # pyright: ignore[reportOptionalMemberAccess]
            data = list(cursor)

            if not data:
                warning_message = "FIPS query returned no results"
                logger.warning(warning_message)
                return pd.DataFrame()

            df = pd.DataFrame(data)
            logger.info(f"Returned {len(df)} FIPS records")
            return df

        except Exception as e:
            error_message = "Error fetching FIPS data from MongoDB"
            logger.exception(error_message)
            raise e

    def get_dataframe(
        self,
        collection_name: CollectionName,
        filter_values: dict[str, Any] | None = None,
    ) -> pd.DataFrame:
        """Get dataset from MongoDB based on collection type.

        :param collection_name: The collection to query (CC or FIPS)
        :param filter_values: Optional dictionary mapping filter IDs to values
        :return: Dataset as DataFrame
        :raises ValueError: If collection_name is not supported
        """
        if collection_name == CollectionName.CommonCriteria:
            return self.get_cc_dataframe(filter_values)
        elif collection_name == CollectionName.FIPS140:
            return self.get_fips_dataframe(filter_values)
        else:
            raise ValueError(f"Unsupported collection type: {collection_name}")

    def execute_aggregation_pipeline(
        self,
        collection_name: CollectionName,
        pipeline: list[dict[str, Any]],
    ) -> pd.DataFrame:
        """Execute a MongoDB aggregation pipeline and return results as DataFrame.

        This is used for charts with custom aggregation queries built from
        user-defined axis configurations and filters.

        :param collection_name: The collection to query (CC or FIPS)
        :param pipeline: MongoDB aggregation pipeline stages
        :return: Aggregated data as DataFrame
        """
        collection_map = {
            CollectionName.CommonCriteria: self.mongo.db.cc,  # pyright: ignore[reportOptionalMemberAccess]
            CollectionName.FIPS140: self.mongo.db.fips,  # pyright: ignore[reportOptionalMemberAccess]
        }

        collection = collection_map.get(collection_name)
        if collection is None:
            raise ValueError(f"Unsupported collection type: {collection_name}")

        logger.info(f"Executing aggregation pipeline on {collection_name}: {pipeline}")

        try:
            cursor = collection.aggregate(pipeline)
            data = list(cursor)

            if not data:
                warning_message = f"[EXEC_AGG_PIPELINE] Aggregation pipeline returned no results for {collection_name}"
                logger.warning(warning_message)
                return pd.DataFrame()

            df = pd.DataFrame(data)
            logger.info(f"[EXEC_AGG_PIPELINE] Aggregation returned {len(df)} records")
            return df

        except Exception as e:
            error_message = f"Error executing aggregation pipeline on {collection_name}"
            logger.exception(error_message)
            raise e

    def get_distinct_values(self, field: str, collection_name) -> list[Any]:
        """Get distinct values for a field from MongoDB.

        This is used to populate filter dropdowns dynamically.

        :param field: MongoDB field name
        :param collection_name: Type of dataset ('cc' or 'fips')
        :return: List of distinct values (sorted)
        """
        collections = {
            "cc": self.mongo.db.cc,  # pyright: ignore[reportOptionalMemberAccess]
            "fips": self.mongo.db.fips,  # pyright: ignore[reportOptionalMemberAccess]
        }

        collection = collections.get(collection_name.lower())
        if collection is None:
            raise ValueError(f"Unknown dataset type: {collection_name}")

        distinct_values = collection.distinct(field)
        values = [v for v in distinct_values if v is not None and v != ""]
        return sorted(values)

    def get_unique_values(self, collection_name: CollectionName, field: str) -> list[Any]:
        """Get unique values for a field from MongoDB.

        This is used to populate filter dropdowns in the chart creation modal.
        For special derived fields like 'year_from', it extracts years from the
        source date field.

        :param collection_name: The collection to query (CC or FIPS)
        :param field: MongoDB field path (e.g., 'category', 'web_data.level')
        :return: List of unique values (sorted, non-null)
        """
        collection_map = {
            CollectionName.CommonCriteria: self.mongo.db.cc,  # pyright: ignore[reportOptionalMemberAccess]
            CollectionName.FIPS140: self.mongo.db.fips,  # pyright: ignore[reportOptionalMemberAccess]
        }

        collection = collection_map.get(collection_name)
        if collection is None:
            raise ValueError(f"Unsupported collection type: {collection_name}")

        try:
            # Handle derived year field
            if field == "year_from":
                return self._get_unique_years(collection, collection_name)

            distinct_values = collection.distinct(field)
            # Filter out None and empty values, then sort
            values = [v for v in distinct_values if v is not None and v != ""]
            try:
                return sorted(values)
            except TypeError:
                # If sorting fails (mixed types), return as-is
                return values
        except Exception:
            error_message = f"[GET_UNIQUE_VALUES] Error getting unique values for field '{field}'"
            logger.exception(error_message)
            raise

    def _get_unique_years(self, collection: Any, collection_name: CollectionName) -> list[int]:
        """Extract unique years from the appropriate date field.

        Handles dates stored as serialized dictionaries with format:
        {"_type": "date", "_value": "YYYY-MM-DD"}

        :param collection: MongoDB collection
        :param collection_name: Type of collection (CC or FIPS)
        :return: Sorted list of unique years
        """
        # Determine the source date field based on collection type
        if collection_name == CollectionName.CommonCriteria:
            date_field = "not_valid_before"
        else:  # FIPS
            date_field = "web_data.date_validation"

        try:
            # Dates are stored as {"_type": "date", "_value": "YYYY-MM-DD"}
            # Extract year from the _value string (first 4 characters)
            pipeline = [
                {"$match": {f"{date_field}._value": {"$exists": True, "$ne": None}}},
                {"$group": {"_id": {"$toInt": {"$substr": [f"${date_field}._value", 0, 4]}}}},
                {"$sort": {"_id": 1}},
            ]
            result = list(collection.aggregate(pipeline))
            years = [doc["_id"] for doc in result if doc["_id"] is not None]
            return years
        except Exception:
            error_message = f"[GET_UNIQUE_YEARS] Error extracting unique years from date field: {date_field}"
            logger.exception(error_message)
            return []

    def get_distinct_values_with_labels(
        self, field: str, collection_name: CollectionName, label_map: dict[str, str] | None = None
    ) -> list[dict[str, str]]:
        """Get distinct values formatted for Dash dropdown options.

        :param field: MongoDB field name
        :param collection_name: Type of dataset ('cc' or 'fips')
        :param label_map: Optional mapping of values to custom labels
        :return: List of {label, value} dicts for Dash dropdowns
        """
        values = self.get_distinct_values(field, collection_name)

        if label_map:
            return [{"label": label_map.get(v, str(v)), "value": v} for v in values]
        else:
            return [{"label": str(v), "value": v} for v in values]

    def _prepare_cc_dataframe(self, data: list[dict]) -> pd.DataFrame:
        """Prepare CC dataframe with proper types and cleaning.

        Applies data type conversions, categorical encoding, and basic cleaning
        to ensure consistent DataFrame structure.

        :param data: List of certificate documents from MongoDB
        :return: Prepared DataFrame
        """
        df = pd.DataFrame(data)

        if "dgst" in df.columns:
            df = df.set_index("dgst")

        # Handle date fields stored as {'_type': 'date', '_value': '...'} dicts
        if "not_valid_before" in df.columns:
            df["not_valid_before"] = df["not_valid_before"].apply(
                lambda x: x.get("_value") if isinstance(x, dict) and "_value" in x else x
            )
            df["not_valid_before"] = pd.to_datetime(df["not_valid_before"], errors="coerce")
        if "not_valid_after" in df.columns:
            df["not_valid_after"] = df["not_valid_after"].apply(
                lambda x: x.get("_value") if isinstance(x, dict) and "_value" in x else x
            )
            df["not_valid_after"] = pd.to_datetime(df["not_valid_after"], errors="coerce")

        # Calculate derived date fields
        if "not_valid_before" in df.columns:
            df["year_from"] = pd.DatetimeIndex(df["not_valid_before"]).year

        # Calculate validity duration (certificate lifetime in days)
        if "not_valid_before" in df.columns and "not_valid_after" in df.columns:
            df["validity_days"] = (df["not_valid_after"] - df["not_valid_before"]).dt.days

        if "heuristics" in df.columns:
            df["cert_lab"] = df["heuristics"].apply(
                lambda x: (x.get("cert_lab", [None])[0] if isinstance(x, dict) and x.get("cert_lab") else None)
            )
            if "eal" not in df.columns:
                df["eal"] = df["heuristics"].apply(lambda x: x.get("eal") if isinstance(x, dict) else None)

        categorical_cols = ["category", "status", "scheme"]
        for col in categorical_cols:
            if col in df.columns:
                df[col] = df[col].astype("category")

        if "cert_lab" in df.columns:
            df["cert_lab"] = df["cert_lab"].astype("category")

        if "manufacturer" in df.columns:
            df = df.loc[~df["manufacturer"].isnull()]

        if "eal" in df.columns:
            df["eal"] = df["eal"].fillna(value=np.nan)
            unique_eals = df["eal"].dropna().unique().tolist()
            if unique_eals:
                df["eal"] = pd.Categorical(
                    df["eal"],
                    categories=sorted(unique_eals),
                    ordered=True,
                )

        return df

    def get_dataset_metadata(self, collection_name: str) -> tuple[dict[str, ColumnStats], int, int]:
        """Get metadata about a dataset including column information.

        :param collection_name: Type of dataset ('cc' or 'fips')
        :return: Tuple of (column_stats, total_records, total_columns) where
                 column_stats maps column names to their statistics
        """
        if collection_name.lower() == "cc":
            df = self.get_cc_dataframe()
        elif collection_name.lower() == "fips":
            df = self.get_fips_dataframe()
        else:
            raise ValueError(f"Unknown dataset type: {collection_name}")

        if df.empty:
            return {}, 0, 0

        column_stats: dict[str, ColumnStats] = {}
        for col in df.columns:
            try:
                non_null_data = df[col].dropna()
                col_info: ColumnStats = {
                    "dtype": str(df[col].dtype),
                    "unique_count": (len(non_null_data.unique()) if not non_null_data.empty else 0),
                    "null_count": int(df[col].isnull().sum()),
                    "total_count": len(df[col]),
                }

                if df[col].dtype in ["int64", "float64"] and not non_null_data.empty:
                    col_info["min_value"] = float(df[col].min())
                    col_info["max_value"] = float(df[col].max())

                if col_info["unique_count"] <= 50 and not non_null_data.empty:
                    col_info["sample_values"] = list(non_null_data.unique())

                column_stats[col] = col_info
            except Exception as e:
                error_message = f"[GET_DATASET_METADATA] Error analyzing column {col}"
                logger.exception(error_message)
                column_stats[col] = {
                    "dtype": str(df[col].dtype),
                    "unique_count": 0,
                    "null_count": 0,
                    "total_count": 0,
                    "error": str(e),
                }

        return column_stats, len(df), len(df.columns)
