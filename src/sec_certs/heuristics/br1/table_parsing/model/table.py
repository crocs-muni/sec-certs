from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

T = TypeVar("T")


def column(header: str) -> Any:
    """
    Field of a table entry, filled from the column with `header`. The header is the one the NIST SP builder
    prints in BR1 security policies, compared ignoring case, whitespace and punctuation (see
    `parser.normalize_header`).
    """
    return field(metadata={"header": header})


@dataclass
class BR1Table(Generic[T]):
    name: str
    section: int
    subsection: int
    entry_type: type[T]
    found: bool = False
    entries: list[T] = field(default_factory=list)
