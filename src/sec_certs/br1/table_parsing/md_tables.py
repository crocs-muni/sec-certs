from typing import List

from markdown_it import MarkdownIt

Row = List[str]
Table = List[Row]
Tables = List[Table]


def filter_table_lines(text: str) -> str:
    """
    Filters "table lines" in case there are dangling table titles or other text
    in between more parts of one table
    """
    return "\n".join(line for line in text.splitlines() if line.strip().startswith("|"))


def is_separator_row(row: Row):
    """Return True if all cells are made only of '-', ':', or spaces."""
    return all(cell.strip() and all(ch in "-: " for ch in cell.strip()) for cell in row)


def parse_markdown_tables(text: str, join_headers: bool = True) -> Tables:
    """
    Parse markdown tables from `text` and return a list of tables.
    Each table is a list of rows (each row is a list of cell strings).
    The first row in each table is the header. Repeated header rows
    (e.g. multipage header repeats) are skipped.
    """
    md = MarkdownIt("gfm-like")  # enable tables
    tokens = md.parse(text)
    tables = []
    last_header = None
    row = []
    current_table = []

    for token in tokens:
        t = token.type

        if t == "inline":  # Content of the cell
            row.append(token.content.strip())

        elif t == "tr_close":
            if join_headers and row == last_header or is_separator_row(row):
                row = []
                continue
            if last_header is None:
                last_header = row
            current_table.append(row)
            row = []

        elif t == "table_close":
            tables.append(current_table)
            current_table = []

    return tables
