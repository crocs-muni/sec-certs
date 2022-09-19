import html
import logging
from datetime import date
from typing import Optional, Set, Union

import numpy as np
import pandas as pd
from bs4 import NavigableString

logger = logging.getLogger(__name__)


def sanitize_navigable_string(string: Optional[Union[NavigableString, str]]) -> Optional[str]:
    if not string:
        return None
    return str(string).strip().replace("\xad", "").replace("\xa0", "")


def sanitize_link(record: Optional[str]) -> Optional[str]:
    if not record:
        return None
    return record.replace(":443", "").replace(" ", "%20").replace("http://", "https://")


def sanitize_date(record: Union[pd.Timestamp, date, np.datetime64]) -> Union[date, None]:
    if pd.isnull(record):
        return None
    elif isinstance(record, pd.Timestamp):
        return record.date()
    elif isinstance(record, (date, type(None))):
        return record
    raise ValueError("Unsupported type given as input")


def sanitize_string(record: str) -> str:
    # There is a sample with name 'ATMEL Secure Microcontroller AT90SC12872RCFT &#x2f; AT90SC12836RCFT rev. I &amp;&#x23;38&#x3b; J' that has to be unescaped twice
    string = html.unescape(html.unescape(record)).replace("\n", "")
    return " ".join(string.split())


def sanitize_security_levels(record: Union[str, Set[str]]) -> Set[str]:
    if isinstance(record, str):
        record = set(record.split(","))
    return record - {"Basic", "ND-PP", "PP\xa0Compliant", "None"}


def sanitize_protection_profiles(record: str) -> list:
    if not record:
        return []
    return record.split(",")
