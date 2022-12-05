from __future__ import annotations

import logging
import re
from pathlib import Path

from sec_certs.cert_rules import FIPS_LIST_OF_TABLES

logger = logging.getLogger(__name__)


def parse_list_of_tables(txt: str) -> set[int]:
    """
    Parses list of tables in policy txt, returns page numbers of tables that mention algorithms
    """
    rr = re.compile(r"^.+?(?:[Ff]unction|[Aa]lgorithm|[Ss]ecurity [Ff]unctions?).+?(?P<page_num>\d+)$", re.MULTILINE)
    return {int(m.group("page_num")) for m in rr.finditer(txt)}


def get_table_rich_page_numbers_from_footer(file_text: str) -> set[int]:
    """
    Parses page numbers of policy txt pages that may contain tables with algorithm data
    """
    current_page = 1
    pages = set()

    for line in file_text.split("\n"):
        if "\f" in line:
            current_page += 1
        if line.startswith("Table ") or line.startswith("Exhibit"):
            pages.add(current_page)
            pages.add(current_page + 1)
            if current_page > 2:
                pages.add(current_page - 1)

    for page in pages:
        if page > current_page - 1:
            return pages - {page}

    return pages


def find_pages_with_tables(txt_filepath: Path) -> set[int]:
    """
    Identifies pages in txt file that may contain tables. Return their page numbers.
    """
    with txt_filepath.open("r", encoding="utf-8") as handle:
        txt = handle.read()

    # Parse page numbers from list of tables if available
    # Else look for "Table" in text and \f representing footer, then extract page number from footer
    if list_of_tables := FIPS_LIST_OF_TABLES.search(txt):
        result = parse_list_of_tables(list_of_tables.group())
    else:
        result = get_table_rich_page_numbers_from_footer(txt)

    return result if result else set()


def get_algs_from_table(dataframe_text: str) -> set[str]:
    reg = r"(?:#?\s?|(?:Cert)\.?[^. ]*?\s?)(?:[CcAa]\s)?(?P<id>[CcAa]? ?\d+)"
    return {m.group() for m in re.finditer(reg, dataframe_text)}
