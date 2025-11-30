from dataclasses import dataclass, field
from typing import Generic, List, Type, TypeVar

T = TypeVar("T")


@dataclass
class BR1Table(Generic[T]):
    name: str
    section: int
    subsection: int
    entry_type: Type[T]
    found: bool = False
    entries: List[T] = field(default_factory=list)
