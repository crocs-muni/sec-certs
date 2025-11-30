from dataclasses import dataclass, field
from typing import List


@dataclass
class Chapter:
    title: str
    subchapters: List["Chapter"] = field(default_factory=list)
    optional: bool = False
    content: str = ""
    found: bool = False
