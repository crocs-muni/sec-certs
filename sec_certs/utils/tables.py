import re
import logging
from pathlib import Path
from typing import Set, List, Optional, Union

logger = logging.getLogger(__name__)


def parse_list_of_tables(txt: str) -> Set[str]:
    """
    Parses list of tables from function find_tables(), finds ones that mention algorithms
    :param txt: chunk of text
    :return: set of all pages mentioning algorithm table
    """
    rr = re.compile(r"^.+?(?:[Ff]unction|[Aa]lgorithm|[Ss]ecurity [Ff]unctions?).+?(?P<page_num>\d+)$", re.MULTILINE)
    pages = set()
    for m in rr.finditer(txt):
        pages.add(m.group("page_num"))
    return pages


def find_tables_iterative(file_text: str) -> List[int]:
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
    if not pages:
        logger.warning("No pages found")
    for page in pages:
        if page > current_page - 1:
            return list(pages - {page})

    return list(pages)


def find_tables(txt: str, file_name: Path) -> Optional[Union[List[str], List[int]]]:
    """
    Function that tries to pages in security policy pdf files, where it's possible to find a table containing
    algorithms
    :param txt: file in .txt format (output of pdftotext)
    :param file_name: name of the file
    :return:    list of pages possibly containing a table
                None if these cannot be found
    """
    # Look for "List of Tables", where we can find exactly tables with page num
    tables_regex = re.compile(r"^(?:(?:[Tt]able\s|[Ll]ist\s)(?:[Oo]f\s))[Tt]ables[\s\S]+?\f", re.MULTILINE)
    table = tables_regex.search(txt)
    if table:
        rb = parse_list_of_tables(table.group())
        if rb:
            return list(rb)
        return None

    # Otherwise look for "Table" in text and \f representing footer, then extract page number from footer
    logger.info(f"parsing tables in {file_name}")
    table_page_indices = find_tables_iterative(txt)
    return table_page_indices if table_page_indices else None