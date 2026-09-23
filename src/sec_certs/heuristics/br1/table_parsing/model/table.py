from dataclasses import asdict, dataclass, field
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

    def to_dict(self) -> dict[str, Any]:
        """The table as saved in the dataset. Its name and entry type are part of the template, not saved."""
        return {
            "section": self.section,
            "subsection": self.subsection,
            "found": self.found,
            "entries": [asdict(entry) for entry in self.entries],  # type: ignore[call-overload]
        }
