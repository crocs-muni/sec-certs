from enum import Enum


class CollectionName(str, Enum):
    """Corresponds to MongoDB collection names."""

    CommonCriteria = "cc"
    FIPS140 = "fips"
