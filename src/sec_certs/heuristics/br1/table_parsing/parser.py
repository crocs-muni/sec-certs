import logging
import re
from dataclasses import fields

from fuzzysearch import find_near_matches

from sec_certs.configuration import config
from sec_certs.heuristics.br1.models.chapter import Chapter
from sec_certs.heuristics.br1.table_parsing.model.br1_tables import BR1Tables

from .md_tables import Row, filter_table_lines, parse_markdown_tables

logger = logging.getLogger(__name__)


def get_chapter(chapters: list[Chapter], chapter_num: int, subchapter_num: int):
    return chapters[chapter_num - 1].subchapters[subchapter_num - 1]


def match_sections_between_headers(text: str, headers: list[str]) -> tuple[dict[str, str], list[str]]:
    """
    Searches for each header of `headers` in the text using fuzzy matching
    (fuzzysearch.find_near_matches), then splits the parts of the `text`
    between the headers and returns them.
    """
    found_matches = []

    for original_header in headers:
        search_term = original_header.strip()

        matches = find_near_matches(
            search_term,
            text,
            max_l_dist=config.br1_max_parsing_deviation,
        )

        if matches:
            best_match = matches[0]

            # The content should start from the next \n
            match_end_index = best_match.end
            newline_match = re.search(r"\n", text[best_match.end :])
            content_start_index = match_end_index + newline_match.end() if newline_match else match_end_index
            found_matches.append(
                {
                    "start": best_match.start,
                    "content_start": content_start_index,
                    "header_name": original_header.strip(),
                }
            )

    found_matches.sort(key=lambda x: x["start"])

    sections = {}
    matched_headers = []

    for i, current_match in enumerate(found_matches):
        current_header = current_match["header_name"]
        start_index = current_match["content_start"]

        end_index = found_matches[i + 1]["start"] if i + 1 < len(found_matches) else len(text)

        content = text[start_index:end_index].strip()

        sections[current_header] = content
        matched_headers.append(current_header)

    return sections, matched_headers


# Section is split into parts by the separator titles
def get_splitted_section(text: str, section: int, subsection: int, name: str, adv_prop: BR1Tables) -> str:
    """
    Extracts the content associated with header name (`name`) from a section.
    Multiple sections contain more tables that are separated by their names.
    This function extracts the part of the section starting immediately after the `name`
    until the next header or the end of `text`
    """
    section_names = [
        getattr(adv_prop, f.name).name
        for f in fields(adv_prop)
        if getattr(adv_prop, f.name).section == section and getattr(adv_prop, f.name).subsection == subsection
    ]
    sections, matched = match_sections_between_headers(text, section_names)
    return "" if name not in matched else sections[name]


def normalize_header(header: str) -> str:
    """Keep only lowercase letters and digits, so that words split by the converter (e.g. "Descripti on") match."""
    return re.sub(r"[^a-z0-9]", "", header.lower())


def map_columns(header: Row, entry_type: type) -> dict[str, int] | None:
    """
    Maps the fields of `entry_type` to the indices of their columns in `header`. Returns None unless the table
    has exactly the columns of `entry_type`, i.e. a column is missing, extra or named differently.
    """
    cells = [normalize_header(cell) for cell in header]
    columns = {f.name: normalize_header(f.metadata["header"]) for f in fields(entry_type)}
    if sorted(cells) != sorted(columns.values()):
        return None
    return {name: cells.index(column) for name, column in columns.items()}


def parse_tables(chapters: list[Chapter]) -> BR1Tables:
    """
    Parse all tables defined in the AdvancedProperties model from the chapters' content.
    """
    res = BR1Tables()
    table = None
    chapter = ""

    for f in fields(res):
        table = getattr(res, f.name)
        chapter = get_chapter(chapters, table.section, table.subsection)
        # If table.name is empty it means there is just 1 table in the section
        if table.name == "":
            content = chapter.content
        # Case when there is more tables in one section, the section is split by separators
        if table.name:
            content = get_splitted_section(chapter.content, table.section, table.subsection, table.name, res)
        tables = parse_markdown_tables(filter_table_lines(content))
        if not tables or len(tables[0]) <= 1:
            continue

        # First row is always the table header
        header, *rows = tables[0]
        columns = map_columns(header, table.entry_type)
        if columns is None:
            logger.debug(f"Header {header} of table {f.name} does not match {table.entry_type.__name__}.")
            continue

        table.found = True
        table.entries = [table.entry_type(**{name: row[i] for name, i in columns.items()}) for row in rows]

    return res
