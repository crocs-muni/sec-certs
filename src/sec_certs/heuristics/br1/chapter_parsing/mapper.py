import re
from collections.abc import Iterable

import regex

from sec_certs.configuration import config
from sec_certs.document.base import BlockKind, DocumentBlock
from sec_certs.heuristics.br1.models.chapter import Chapter

from .chapter_utils import chapters_from_json, traverse_chapters


def substitute(title: str) -> str:
    """Remove spaces and dashes."""
    return re.sub(r"[ \-–—‒]", "", title)


def build_chapter_regex(chapters: list[Chapter], chapter_num: int, subchapter_num: int) -> str:
    """Construct a fuzzy regex for chapter titles."""
    base_chapter = chapters[chapter_num - 1]
    title = base_chapter.title
    if subchapter_num > 0:
        title = base_chapter.subchapters[subchapter_num - 1].title

    title = substitute(title)

    return rf"^(Section)*{chapter_num}(\.?{subchapter_num})?\.?{title}$"


def is_heading_candidate(block: DocumentBlock) -> bool:
    """Headings, and lines of text starting with a digit, as numbered headings are sometimes recognized as text."""
    return block.kind is BlockKind.HEADING or (block.kind is BlockKind.TEXT and block.text.strip()[:1].isnumeric())


def append_block(chapter: Chapter, block: DocumentBlock) -> None:
    """Append the text of `block` to the content of `chapter`, recording where a table starts."""
    if block.table is not None:
        chapter.tables.append((len(chapter.content) + 1, block.table))
    for line in block.text.splitlines():
        if line.strip():
            chapter.content += "\n" + line.strip()


def extract_chapters(blocks: Iterable[DocumentBlock]) -> list[Chapter]:
    """
    Split the blocks of a document into chapters by their headings. Returns a list of chapters with the
    .found attribute set and the .content and .tables attributes filled. The headings are not a part of the
    chapter contents. The matching is case insensitive, allows a number of errors in the heading text, which
    can be configured via config.br1_max_parsing_deviation.
    """
    chapters = chapters_from_json()
    curr_chapter, curr_subchapter = 0, 0
    inside_chapter = False

    for block in blocks:
        stripped = block.text.strip()
        if stripped == "":
            continue

        matched = False
        if is_heading_candidate(block):
            for _, (ch_num, sub_num) in traverse_chapters(chapters):
                if ch_num < curr_chapter:  # TODO can this happen
                    continue

                ## Match regex with a number of allowed errors
                pattern = regex.compile(
                    f"({build_chapter_regex(chapters, ch_num, sub_num)}){{e<={config.br1_max_parsing_deviation}}}",
                    flags=regex.IGNORECASE,
                )
                if pattern.match(substitute(stripped)):
                    inside_chapter, matched = True, True
                    curr_chapter, curr_subchapter = ch_num, sub_num

                    # Needs to be reduced because chapters are numbered from 1
                    chapter = (
                        chapters[curr_chapter - 1]
                        if curr_subchapter == 0
                        else chapters[curr_chapter - 1].subchapters[curr_subchapter - 1]
                    )
                    chapter.found = True
                    break

                if matched:
                    break

        if not matched and inside_chapter:
            chapter = (
                chapters[curr_chapter - 1]
                if curr_subchapter == 0
                else chapters[curr_chapter - 1].subchapters[curr_subchapter - 1]
            )
            append_block(chapter, block)

    return chapters
