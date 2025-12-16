from dataclasses import dataclass, field
from typing import Generic, TypeVar

T = TypeVar("T")


@dataclass
class BR1Table(Generic[T]):
    name: str
    section: int
    subsection: int
    entry_type: type[T]
    found: bool = False
    entries: list[T] = field(default_factory=list)
