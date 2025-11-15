"""Data management layer with caching (Redis) and MongoDB integration.

This module provides the DataService class, which is responsible for fetching
and caching data from MongoDB collections.
"""

import logging
from typing import Any, Dict, List

import numpy as np
import pandas as pd
from flask_pymongo import PyMongo

logger = logging.getLogger(__name__)


class DataService:
    _df_cc = None
    _df_fips = None

    def __init__(self, mongo: PyMongo):
        self.mongo = mongo

    def get_cc_dataframe(self) -> pd.DataFrame:
        if self._df_cc is None:
            logger.info("Fetching Common Criteria dataset from MongoDB...")
            try:
                cursor = self.mongo.db.cc.find({})  # pyright: ignore[reportOptionalMemberAccess]
                data = list(cursor)
                if data:
                    self._df_cc = pd.DataFrame(data)
                    self._df_cc = self._df_cc.set_index("dgst")
                    self._df_cc.not_valid_before = pd.to_datetime(self._df_cc.not_valid_before, errors="coerce")
                    self._df_cc.not_valid_after = pd.to_datetime(self._df_cc.not_valid_after, errors="coerce")
                    self._df_cc = self._df_cc.astype(
                        {
                            "category": "category",
                            "status": "category",
                            "scheme": "category",
                            "cert_lab": "category",
                        }
                    ).fillna(value=np.nan)
                    self._df_cc = self._df_cc.loc[
                        ~self._df_cc.manufacturer.isnull()
                    ]  # Manually delete one certificate with None manufacturer (seems to have many blank fields)

                    # Categorize EAL
                    self._df_cc.eal = self._df_cc.eal.fillna(value=np.nan)
                    self._df_cc.eal = pd.Categorical(
                        self._df_cc.eal, categories=sorted(self._df_cc.eal.dropna().unique().tolist()), ordered=True
                    )

                    self._df_cc["year_from"] = pd.DatetimeIndex(self._df_cc.not_valid_before).year
                else:
                    logger.warning("CC collection is empty.")
                    return pd.DataFrame()
            except Exception as e:
                error_message = "Error fetching CC data from MongoDB"
                logger.exception(error_message)
                raise e
        return self._df_cc

    def get_fips_dataframe(self) -> pd.DataFrame:
        """
        Fetches the FIPS dataset from the 'fips' collection in MongoDB.
        """
        if self._df_fips is None:
            print("Fetching FIPS dataset from MongoDB...")
            try:
                cursor = self.mongo.db.fips.find({})  # pyright: ignore[reportOptionalMemberAccess]
                data = list(cursor)
                if data:
                    self._df_fips = pd.DataFrame(data)
                else:
                    logger.warning("FIPS collection is empty.")
                    return pd.DataFrame()
            except Exception as e:
                logger.exception("Error fetching FIPS data from MongoDB")
                raise e
        return self._df_fips

    def get_dataset_metadata(self, dataset_type: str) -> Dict[str, Any]:
        """
        Get metadata about a dataset including column information.

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

                # Add range information for numeric columns
                if df[col].dtype in ["int64", "float64"] and not non_null_data.empty:
                    col_info["min_value"] = float(df[col].min())
                    col_info["max_value"] = float(df[col].max())

                # Add sample values for categorical columns (limited unique values)
                if col_info["unique_count"] <= 50 and not non_null_data.empty:
                    col_info["sample_values"] = list(non_null_data.unique())

                columns_info.append(col_info)
            except Exception as e:
                logger.warning(f"Error analyzing column {col}: {e}")
                columns_info.append({"name": col, "dtype": str(df[col].dtype), "error": str(e)})

        return {"total_records": len(df), "total_columns": len(df.columns), "columns": columns_info}

    def get_filterable_columns(self, dataset_type: str) -> List[str]:
        """
        Get list of column names that are suitable for filtering.

        :param dataset_type: Type of dataset ('cc' or 'fips')
        :return: List of filterable column names
        """
        metadata = self.get_dataset_metadata(dataset_type)
        filterable = []

        for col_info in metadata["columns"]:
            if "error" in col_info:
                continue

            # Skip columns with complex types or all null values
            if col_info["unique_count"] == 0:
                continue

            # Include numeric, categorical (<=50 unique), and text columns
            if (
                col_info["dtype"] in ["int64", "float64"]
                or col_info["unique_count"] <= 50
                or col_info["dtype"] == "object"
            ):
                filterable.append(col_info["name"])

        return filterable
