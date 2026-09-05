"""Parsing of the SESIP certificate index from TrustCB"""

from __future__ import annotations

import html
import re

INDEX_URL = "https://trustcb.com/iot/sesip/sesip-certificates/"

# header to field name
COLUMN_HEADERS: dict[str, str] = {
    "Cert. ID": "cert_id",
    "Issue Date": "issue_date",
    "Product": "product",
    "Developer": "developer",
    "Evaluator": "evaluator",
    "Compliance": "compliance",
    "Standard": "standard",
    "Status": "status",
    "Cert": "cert_link",
    "ST": "st_link",
}

_TABLE_RE = re.compile(r'<table[^>]*class="[^"]*wpDataTable[^"]*"[^>]*>(.*?)</table>', re.DOTALL)
_TBODY_RE = re.compile(r"<tbody>(.*?)</tbody>", re.DOTALL)
_ROW_RE = re.compile(r"<tr[^>]*>(.*?)</tr>", re.DOTALL)
_TH_RE = re.compile(r"<th[^>]*>(.*?)</th>", re.DOTALL)
_TD_RE = re.compile(r"<td[^>]*>(.*?)</td>", re.DOTALL)
_HREF_RE = re.compile(r'href="([^"]+)"')
_BR_RE = re.compile(r"<br\s*/?>", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")


class UnexpectedIndexSchema(ValueError):
    """The portal table no longer has the columns we know how to read"""


def _cell_text(cell: str) -> str:
    # <br> separates words inside a cell
    return re.sub(r"\s+", " ", html.unescape(_TAG_RE.sub("", _BR_RE.sub(" ", cell)))).strip()


def _cell_value(cell: str) -> str:
    match = _HREF_RE.search(cell)
    return html.unescape(match.group(1)) if match else _cell_text(cell)


def parse_index_table(page: str) -> list[dict[str, str]]:
    # parsing the index table into one dict per certificate

    # return = rows keyed by the field names in :data:`COLUMN_HEADERS`
    table = _TABLE_RE.search(page)
    if not table:
        raise UnexpectedIndexSchema("no wpDataTable element found on the page")

    headers = [_cell_text(th) for th in _TH_RE.findall(table.group(1))]
    unknown = set(headers) - set(COLUMN_HEADERS)
    missing = set(COLUMN_HEADERS) - set(headers)
    if unknown or missing:
        raise UnexpectedIndexSchema(f"unexpected columns (extra={sorted(unknown)}, missing={sorted(missing)})")
    fields = [COLUMN_HEADERS[h] for h in headers]

    body = _TBODY_RE.search(table.group(1))
    if not body:
        raise UnexpectedIndexSchema("table has no tbody")

    rows = []
    for row in _ROW_RE.findall(body.group(1)):
        cells = _TD_RE.findall(row)
        if len(cells) != len(fields):
            raise UnexpectedIndexSchema(f"row has {len(cells)} cells, expected {len(fields)}")
        rows.append(dict(zip(fields, (_cell_value(c) for c in cells))))
    return rows
