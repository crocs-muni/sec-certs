from __future__ import annotations

import itertools
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    import pandas as pd

logger = logging.getLogger(__name__)


class DocumentLayer(str, Enum):
    BODY = "body"
    FURNITURE = "furniture"


@dataclass(frozen=True)
class DocumentTable:
    """
    A single logical table, fully detached from the backend that produced it.

    Holds only strings, tuples and enums, so it survives pickling across a process pool and keeps no
    reference to the parsed document it came from.
    """

    rows: tuple[tuple[str, ...], ...] = ()
    """Body rows, header excluded. Rectangular: every row has the same length."""

    header: tuple[tuple[str, ...], ...] = ()
    """Leading header rows, possibly none."""

    caption: str | None = None
    """Caption of the table, e.g. `Table 4: Approved Algorithms`. None when the table has no caption."""

    pages: tuple[int, ...] = ()
    """1-based numbers of all pages this table covers, ascending."""

    is_index: bool = False
    """Whether this is a table-of-contents-like block (list of tables, list of figures) rather than data."""

    n_fragments: int = 1
    """Number of per-page fragments this table was stitched from. 1 means it was not split across pages."""

    @property
    def n_cols(self) -> int:
        first = self.header[0] if self.header else (self.rows[0] if self.rows else ())
        return len(first)

    @property
    def n_rows(self) -> int:
        return len(self.header) + len(self.rows)

    @property
    def is_empty(self) -> bool:
        return self.n_rows == 0 or self.n_cols == 0

    def column_names(self) -> list[str] | None:
        """
        Column names flattened out of the header rows, or None when the table has no header.

        Rows of unequal length are padded rather than truncated, so the result always covers every column.
        """
        if not self.header:
            return None
        return [".".join(part for part in parts if part) for parts in itertools.zip_longest(*self.header, fillvalue="")]

    def to_dataframe(self) -> pd.DataFrame:
        import pandas as pd

        return pd.DataFrame(list(self.rows), columns=self.column_names())

    def to_text(self, cell_sep: str = " ", row_sep: str = "\n", include_header: bool = True) -> str:
        source = (self.header + self.rows) if include_header else self.rows
        return row_sep.join(cell_sep.join(cell.strip() for cell in row) for row in source)


class TablesNotSupportedError(NotImplementedError):
    """
    Raised by views whose backend cannot recover table structure.
    """


class DocumentView(ABC):
    supports_tables: ClassVar[bool] = False

    @property
    @abstractmethod
    def artifact_path(self) -> Path:
        """
        Path to the file this view reads.
        """
        raise NotImplementedError("Not meant to be implemented by the base class.")

    @abstractmethod
    def get_full_text(self, layers: set[DocumentLayer] | None = None) -> str:
        """
        Get the whole unformatted text of the document

        :param layers: content layers to include, all of them when None.
        """
        raise NotImplementedError("Not meant to be implemented by the base class.")

    def get_tables(self, include_index: bool = False, stitch: bool = True) -> list[DocumentTable]:
        """
        Get the structured tables of the document body, in reading order.

        :param include_index: whether to also return table-of-contents-like blocks.
        :param stitch: whether to merge fragments of a table split across a page boundary into one table.
        :raises TablesNotSupportedError: when the backend cannot recover table structure.
        """
        raise TablesNotSupportedError(
            f"{type(self).__name__} cannot extract tables from {self}. "
            "Table extraction requires the docling PDF converter."
        )

    def __str__(self) -> str:
        return f"{type(self).__name__}({self.artifact_path})"
