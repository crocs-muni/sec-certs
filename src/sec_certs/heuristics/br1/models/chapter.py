from dataclasses import dataclass, field

from sec_certs.document.base import DocumentTable


@dataclass
class Chapter:
    title: str
    subchapters: list["Chapter"] = field(default_factory=list)
    optional: bool = False
    content: str = ""
    found: bool = False
    tables: list[tuple[int, DocumentTable]] = field(default_factory=list)
    """Tables of the chapter, each with the offset in `content` at which its text starts."""
