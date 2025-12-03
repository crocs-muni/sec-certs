from dataclasses import dataclass, field


@dataclass
class Chapter:
    title: str
    subchapters: list["Chapter"] = field(default_factory=list)
    optional: bool = False
    content: str = ""
    found: bool = False
