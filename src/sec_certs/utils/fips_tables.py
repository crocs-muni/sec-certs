from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from sec_certs.cert_rules import (
    FIPS_ALG_CERT_COLUMN,
    FIPS_ALG_COLUMN_EXCLUDE,
    FIPS_ALG_ID_BARE,
    FIPS_ALG_ID_CAVP,
    FIPS_ALG_ID_CELL,
    FIPS_ALG_ID_MARKED,
    FIPS_ALG_TABLE_HINT,
)
from sec_certs.configuration import config

if TYPE_CHECKING:
    from sec_certs.document.base import DocumentTable, DocumentView

logger = logging.getLogger(__name__)

SelectedBy = Literal["caption", "header", "cert_column", "continuation", "fallback"]
"""Why a table was picked for scanning. `fallback` means no table in the document looked like one."""

_WHITESPACE = re.compile(r"\s+")
_DISCARDED = str.maketrans("", "", "\u00ad\u200b\u200c\u2060\ufeff")


@dataclass(frozen=True)
class TableHit:
    """A table that contributed to the extraction, kept for logging and testing."""

    caption: str | None
    pages: tuple[int, ...]
    selected_by: SelectedBy
    algorithms: frozenset[str]


@dataclass
class AlgorithmExtraction:
    algorithms: set[str] = field(default_factory=set)
    """Canonical validation numbers, e.g. `#1234`, `#A1234`."""

    hits: list[TableHit] = field(default_factory=list)
    n_tables: int = 0
    """Number of candidate tables in the document"""

    used_fallback: bool = False
    """Whether no table looked like an algorithm table and all of them were scanned strictly instead."""


def normalize(text: str) -> str:
    """
    Collapse whitespace and drop invisible characters, so that regexes see predictable text.

    Zero-width characters are deleted rather than turned into spaces: a zero-width space inside
    `#A2\u200b820` would otherwise split a single validation number into `#A2` and a stray `820`.
    """
    return _WHITESPACE.sub(" ", text.translate(_DISCARDED)).strip()


def canonical_id(prefix: str | None, number: str) -> str:
    """Render a match as `#<PREFIX><number>`, dropping any leading zeros of the number."""
    return f"#{(prefix or '').upper()}{int(number)}"


def extract_algorithms_from_tables(tables: Sequence[DocumentTable]) -> AlgorithmExtraction:
    """
    Extract algorithm validation numbers from the tables of a security policy.

    Tables whose caption or header mentions algorithms or certificate numbers are scanned leniently;
    if no table in the document looks like that, every table is scanned for explicitly marked numbers
    instead.

    :param tables: tables of a single document, in reading order.
    """
    # A table-of-contents entry reads "Table 4: Approved Algorithms ....... 12": it matches every caption
    # hint and ends in a bare page number, so it would be the worst possible thing to scan.
    candidates = [table for table in tables if not table.is_index and not table.is_empty]
    result = AlgorithmExtraction(n_tables=len(candidates))

    selection = _select(candidates)
    if candidates and not selection:
        result.used_fallback = True
        selection = dict.fromkeys(range(len(candidates)), "fallback")

    for index, table in enumerate(candidates):
        selected_by = selection.get(index)
        if selected_by is None:
            continue
        algorithms = _plausible(_ids_from_table(table, lenient=selected_by != "fallback"))
        if algorithms:
            result.algorithms |= algorithms
            result.hits.append(
                TableHit(
                    caption=table.caption,
                    pages=table.pages,
                    selected_by=selected_by,
                    algorithms=frozenset(algorithms),
                )
            )

    return result


def extract_algorithms_from_view(view: DocumentView) -> AlgorithmExtraction:
    """
    Extract algorithm validation numbers from the tables of the document behind `view`.

    :raises TablesNotSupportedError: when the view's backend cannot recover table structure.
    """
    return extract_algorithms_from_tables(view.get_tables())


def _select(tables: Sequence[DocumentTable]) -> dict[int, SelectedBy]:
    """Pick the tables that look like they list algorithms, keyed by their index in `tables`."""
    selection: dict[int, SelectedBy] = {}

    for index, table in enumerate(tables):
        if table.caption and FIPS_ALG_TABLE_HINT.search(normalize(table.caption)):
            selection[index] = "caption"
        elif any(FIPS_ALG_TABLE_HINT.search(normalize(cell)) for cell in _header_cells(table)):
            selection[index] = "header"
        elif any(_is_cert_column(cell) for cell in _header_cells(table)):
            # A column that announces itself as holding certificate numbers is enough on its own. This
            # catches the FIPS 140-3 key and SSP tables, whose "Security Function and Cert. Number" column
            # the hints miss whenever layout recognition splits the words apart.
            selection[index] = "cert_column"

    if selection:
        _add_continuations(tables, selection)
    return selection


def _add_continuations(tables: Sequence[DocumentTable], selection: dict[int, SelectedBy]) -> None:
    """
    Also select the later pages of a table that was split across a page boundary.

    A continuation repeats its header but carries no caption of its own. Stitching merges most of them
    already; this catches the ones it could not, which is harmless because the numbers of every selected
    table are unioned anyway. It must follow the table it continues — matching one that precedes it means
    the two merely share a header shape.
    """
    earliest: dict[tuple[str, ...], int] = {}
    for index in selection:
        signature = _signature(tables[index])
        if signature:
            page = min(tables[index].pages, default=0)
            earliest[signature] = min(earliest.get(signature, page), page)

    for index, table in enumerate(tables):
        signature = _signature(table)
        if index in selection or signature not in earliest:
            continue
        if min(table.pages, default=0) >= earliest[signature]:
            selection[index] = "continuation"


def _header_cells(table: DocumentTable) -> tuple[str, ...]:
    """Header cells of the table, falling back to its first row when no header was recognized."""
    if table.header:
        return tuple(cell for row in table.header for cell in row)
    return table.rows[0] if table.rows else ()


def _signature(table: DocumentTable) -> tuple[str, ...]:
    return tuple(normalize(cell).casefold() for cell in _header_cells(table))


def _is_cert_column(header_cell: str) -> bool:
    text = normalize(header_cell)
    return bool(FIPS_ALG_CERT_COLUMN.search(text)) and not FIPS_ALG_COLUMN_EXCLUDE.search(text)


def _plausible(ids: set[str]) -> set[str]:
    """
    Drop numbers too low to be a certificate reference.

    Security policies are full of `PKCS #1`, `self test #2`, footnote markers and row counters, which the
    markers around them make indistinguishable from a validation number. Nothing below the threshold can
    take part in reference pruning anyway, so keeping them would only pad the dataset.
    """
    return {i for i in ids if int(re.sub(r"\D", "", i)) > config.always_false_positive_fips_cert_id_threshold}


def _cert_columns(table: DocumentTable) -> set[int]:
    """
    Indices of the columns that announce themselves as holding certificate numbers.

    Resolved per column rather than over the flattened header cells, because a header spanning several
    rows would otherwise place its later rows beyond the table's column count and be ignored. Cells
    spanning several columns arrive repeated across every column they cover, so a spanning
    "Security Function and Cert. Number" marks all of them.
    """
    if table.header:
        width = max(len(row) for row in table.header)
        return {
            column
            for column in range(width)
            if any(_is_cert_column(row[column]) for row in table.header if column < len(row))
        }
    if table.rows:
        return {column for column, cell in enumerate(table.rows[0]) if _is_cert_column(cell)}
    return set()


def _ids_from_table(table: DocumentTable, lenient: bool) -> set[str]:
    """
    Validation numbers in a table's cells.

    :param lenient: whether to also read unmarked numbers out of certificate-number columns. Off for
        tables reached only by the all-tables fallback, where nothing vouches for what a number means.
    """
    cert_columns = _cert_columns(table)
    ids: set[str] = set()

    for row in table.rows:
        for column, cell in enumerate(row):
            text = normalize(cell)
            if not text:
                continue

            ids |= {canonical_id(m.group("prefix"), m.group("id")) for m in FIPS_ALG_ID_MARKED.finditer(text)}

            if not (lenient and column in cert_columns):
                continue

            # In a column that announced itself as holding certificate numbers, the prefixed CAVP form is
            # unmistakable even surrounded by other text, e.g. "Version 3.3: A3045, A3053".
            ids |= {canonical_id(m.group("prefix"), m.group("id")) for m in FIPS_ALG_ID_CAVP.finditer(text)}

            # Numbers without any prefix or marker additionally need the cell to hold nothing but numbers,
            # or key sizes, dates and document references would all read as validation numbers.
            if FIPS_ALG_ID_CELL.fullmatch(text):
                ids |= {canonical_id(m.group("prefix"), m.group("id")) for m in FIPS_ALG_ID_BARE.finditer(text)}

    return ids
