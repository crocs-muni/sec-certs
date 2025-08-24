"""Data management layer with caching (Redis) and MongoDB integration.

This module provides the DataService class, which is responsible for fetching
and caching data from MongoDB collections.
"""

import logging

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
