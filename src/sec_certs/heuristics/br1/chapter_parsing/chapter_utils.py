import json
import logging
from collections.abc import Iterator
from dataclasses import asdict
from pathlib import Path

from sec_certs.heuristics.br1.config.constants import INDENT
from sec_certs.heuristics.br1.models.chapter import Chapter

logger = logging.getLogger(__name__)


def traverse_chapters(chapters: list[Chapter]) -> Iterator[tuple[str, tuple[int, int]]]:
    """
    Iterate through all chapters and subchapters.
    Returns chapter title and a pair of chapter number, subchapter number,
    e.g: Title, (1,0); Title, (1,1); Title, (1,2); ...
    Chapters are numbered from 1 to be consistent with the actual chapters definition.
    If subchapter is 0 it means it's a top-level chapter, subchapter >=1 means it's
    a subchapter.
    """
    for i, chapter in enumerate(chapters, 1):
        yield chapter.title, (i, 0)
        for j, sub in enumerate(chapter.subchapters, 1):
            yield sub.title, (i, j)


def chapters_to_json(chapters: list[Chapter], file: Path, output_dir: Path) -> None:
    """Save chapter structure into formatted JSON."""
    filename = file.stem
    logger.info(f"\nExporting file as json ... {output_dir}/{filename}.json")
    output_file = output_dir / (filename + ".json")
    with output_file.open("w", encoding="utf-8") as f:
        json.dump([asdict(ch) for ch in chapters], f, indent=INDENT)


def chapter_from_dict(data: dict) -> Chapter:
    """Recursively reconstruct a Chapter (and subchapters) from a dict."""
    return Chapter(
        title=data["title"],
        subchapters=[chapter_from_dict(sc) for sc in data.get("subchapters", [])],
        optional=data.get("optional", False),
        content=data.get("content", ""),
        found=data.get("found", False),
    )


def chapters_from_json(file_path: Path) -> list[Chapter]:
    """Load a list of Chapter objects from a JSON string."""
    with file_path.open(encoding="utf-8") as f:
        json_str = f.read()
    data = json.loads(json_str)
    return [chapter_from_dict(ch) for ch in data]
