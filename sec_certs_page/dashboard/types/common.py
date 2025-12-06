from enum import Enum


class CollectionType(str, Enum):
    CommonCriteria = "cc"
    FIPS140 = "fips"
