from __future__ import annotations

import html
import logging
import re
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pandas as pd
from bs4 import NavigableString

logger = logging.getLogger(__name__)


def sanitize_navigable_string(string: NavigableString | str | None) -> str | None:
    if not string:
        return None
    rex = re.compile(r"\s+")
    string = str(string).strip().replace("\xad", "").replace("\xa0", "")
    return rex.sub(" ", string)


def sanitize_link(record: str | None) -> str | None:
    if not record:
        return None
    return record.replace(":443", "").replace(" ", "%20").replace("http://", "https://")


def sanitize_link_fname(record: str | None) -> str | None:
    if not record:
        return None
    parsed = urlparse(record)
    return Path(parsed.path).name


def sanitize_cc_link(record: str | None) -> str | None:
    record = sanitize_link(record)
    if not record:
        return None
    record = record.replace("nfs/ccpfiles/", "")
    if record == "https://www.commoncriteriaportal.org/files/epfiles/":
        return None
    return record


def sanitize_date(record: pd.Timestamp | date | np.datetime64) -> date | None:
    if pd.isnull(record):
        return None
    if isinstance(record, pd.Timestamp):
        return record.date()
    if isinstance(record, date | type(None)):
        return record
    raise ValueError("Unsupported type given as input")


def sanitize_string(record: str) -> str:
    # There is a sample with name 'ATMEL Secure Microcontroller AT90SC12872RCFT &#x2f; AT90SC12836RCFT rev. I &amp;&#x23;38&#x3b; J' that has to be unescaped twice
    string = html.unescape(html.unescape(record)).replace("\n", "")
    return " ".join(string.split())


def sanitize_security_levels(record: str | set[str]) -> set[str]:
    if isinstance(record, str):
        record = set(record.split(","))
    return record - {"Basic", "ND-PP", "PP\xa0Compliant", "None", "Medium", ""}


def sanitize_protection_profiles(record: str) -> list:
    if not record:
        return []
    return record.split(",")
