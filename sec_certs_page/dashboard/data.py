"""Data management layer with MongoDB query filtering.

This module provides DataService for querying MongoDB with optional filters.
Data is not cached in memory - caching is handled by a separate layer (e.g., Redis).

Design decisions:
- No in-memory caching (delegated to external caching layer)
- Always queries MongoDB for fresh data
- Supports filtered and unfiltered queries
- QueryBuilder integration for type-safe query construction
"""

import logging
from logging import Logger
from typing import Any, Dict, Optional

import numpy as np
import pandas as pd
from flask_pymongo import PyMongo

from sec_certs_page.dashboard.filters.query_builder import build_query_from_filters

logger: Logger = logging.getLogger(__name__)


class DataService:
    """Data service for querying MongoDB with optional filtering.

    This service queries MongoDB on every call without in-memory caching.
    Caching should be implemented as a separate layer (e.g., Redis).

    Design rationale:
    - Separation of concerns: data access vs. caching
    - Always returns fresh data from database
    - Lower memory footprint
    - Simplified logic
    """

    def __init__(self, mongo: PyMongo):
        """Initialize data service.

        :param mongo: Flask-PyMongo instance
        """
        self.mongo = mongo

    def get_cc_dataframe(self, filter_values: Optional[Dict[str, Any]] = None) -> pd.DataFrame:
        """Get CC dataset from MongoDB with optional filtering.

        This method always queries MongoDB for fresh data. If you need caching,
        implement it at a higher layer (e.g., Redis, application cache).

        :param filter_values: Optional dictionary mapping filter IDs to values
        :return: CC dataset as DataFrame (filtered or complete)
        """
        # Build query from filters or use empty query for all documents
        query = build_query_from_filters(filter_values, dataset_type="cc") if filter_values else {}

        logger.info(f"Fetching CC dataset from MongoDB with query: {query}")

        try:
            cursor = self.mongo.db.cc.find(query)  # pyright: ignore[reportOptionalMemberAccess]
            data = list(cursor)

            if not data:
                logger.warning("CC query returned no results")
                return pd.DataFrame()

            df = self._prepare_cc_dataframe(data)
            logger.info(f"Returned {len(df)} CC records")
            return df

        except Exception as e:
            logger.exception("Error fetching CC data from MongoDB")
            raise e

    def get_fips_dataframe(self, filter_values: Optional[Dict[str, Any]] = None) -> pd.DataFrame:
        """Get FIPS dataset from MongoDB with optional filtering.

        This method always queries MongoDB for fresh data. If you need caching,
        implement it at a higher layer (e.g., Redis, application cache).

        :param filter_values: Optional dictionary mapping filter IDs to values
        :return: FIPS dataset as DataFrame (filtered or complete)
        """
        # Build query from filters or use empty query for all documents
        query = build_query_from_filters(filter_values, dataset_type="fips") if filter_values else {}

        logger.info(f"Fetching FIPS dataset from MongoDB with query: {query}")

        try:
            cursor = self.mongo.db.fips.find(query)  # pyright: ignore[reportOptionalMemberAccess]
            data = list(cursor)

            if not data:
                logger.warning("FIPS query returned no results")
                return pd.DataFrame()

            df = pd.DataFrame(data)
            logger.info(f"Returned {len(df)} FIPS records")
            return df

        except Exception as e:
            logger.exception("Error fetching FIPS data from MongoDB")
            raise e

    def get_distinct_values(self, field: str, dataset_type: str = "cc") -> list[Any]:
        """Get distinct values for a field from MongoDB.

        This is used to populate filter dropdowns dynamically.

        :param field: MongoDB field name
        :param dataset_type: Type of dataset ('cc' or 'fips')
        :return: List of distinct values (sorted)
        """
        collection = (
            self.mongo.db.cc  # pyright: ignore[reportOptionalMemberAccess]
            if dataset_type.lower() == "cc"
            else self.mongo.db.fips  # pyright: ignore[reportOptionalMemberAccess]
        )

        # Get distinct values, filtering out None/null
        distinct_values = collection.distinct(field)
        # Filter out None and empty strings, then sort
        values = [v for v in distinct_values if v is not None and v != ""]
        return sorted(values)

    def get_distinct_values_with_labels(
        self, field: str, dataset_type: str = "cc", label_map: Optional[Dict[str, str]] = None
    ) -> list[Dict[str, str]]:
        """Get distinct values formatted for Dash dropdown options.

        :param field: MongoDB field name
        :param dataset_type: Type of dataset ('cc' or 'fips')
        :param label_map: Optional mapping of values to custom labels
        :return: List of {label, value} dicts for Dash dropdowns
        """
        values = self.get_distinct_values(field, dataset_type)

        if label_map:
            return [{"label": label_map.get(v, str(v)), "value": v} for v in values]
        else:
            return [{"label": str(v), "value": v} for v in values]

    def _prepare_cc_dataframe(self, data: list[Dict]) -> pd.DataFrame:
        """Prepare CC dataframe with proper types and cleaning.

        Applies data type conversions, categorical encoding, and basic cleaning
        to ensure consistent DataFrame structure.

        :param data: List of certificate documents from MongoDB
        :return: Prepared DataFrame
        """
        df = pd.DataFrame(data)
        df = df.set_index("dgst")

        df.not_valid_before = pd.to_datetime(df.not_valid_before, errors="coerce")
        df.not_valid_after = pd.to_datetime(df.not_valid_after, errors="coerce")

        df = df.astype(
            {
                "category": "category",
                "status": "category",
                "scheme": "category",
                "cert_lab": "category",
            }
        ).fillna(value=np.nan)

        df = df.loc[~df.manufacturer.isnull()]

        if "eal" in df.columns:
            df.eal = df.eal.fillna(value=np.nan)
            df.eal = pd.Categorical(
                df.eal,
                categories=sorted(df.eal.dropna().unique().tolist()),
                ordered=True,
            )

        df["year_from"] = pd.DatetimeIndex(df.not_valid_before).year

        return df

    def get_dataset_metadata(self, dataset_type: str) -> Dict[str, Any]:
        """Get metadata about a dataset including column information.

        :param dataset_type: Type of dataset ('cc' or 'fips')
        :return: Dictionary containing dataset metadata
        """
        if dataset_type.lower() == "cc":
            df = self.get_cc_dataframe()
        elif dataset_type.lower() == "fips":
            df = self.get_fips_dataframe()
        else:
            raise ValueError(f"Unknown dataset type: {dataset_type}")

        if df.empty:
            return {"total_records": 0, "total_columns": 0, "columns": []}

        columns_info = []
        for col in df.columns:
            try:
                non_null_data = df[col].dropna()
                col_info = {
                    "name": col,
                    "dtype": str(df[col].dtype),
                    "unique_count": len(non_null_data.unique()) if not non_null_data.empty else 0,
                    "null_count": df[col].isnull().sum(),
                    "total_count": len(df[col]),
                }

                if df[col].dtype in ["int64", "float64"] and not non_null_data.empty:
                    col_info["min_value"] = float(df[col].min())
                    col_info["max_value"] = float(df[col].max())

                if col_info["unique_count"] <= 50 and not non_null_data.empty:
                    col_info["sample_values"] = list(non_null_data.unique())

                columns_info.append(col_info)
            except Exception as e:
                logger.warning(f"Error analyzing column {col}: {e}")
                columns_info.append({"name": col, "dtype": str(df[col].dtype), "error": str(e)})

        return {"total_records": len(df), "total_columns": len(df.columns), "columns": columns_info}
