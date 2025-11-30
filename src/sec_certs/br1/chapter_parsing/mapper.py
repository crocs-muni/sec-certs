import re
from pathlib import Path

import regex

import sec_certs.br1.config.constants as config
from sec_certs.br1.models.chapter import Chapter

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

    return rf"^(##|Section)*{chapter_num}(\.?{subchapter_num})?\.?{title}$"


# Core extraction logic
def extract_chapters_from_text(text: str) -> list[Chapter]:
    """
    Extract text between chapter boundaries from the given text. Returns a list
    of chapters and fills the .found attribute and .content attribute to appropriate
    value. The chapter titles are not a part of the chapter contents. The matching is case
    insensitive, allows a number of errors in the heading text, which can be configured via
    config.MAX_DEVIATION.
    """
    chapters = chapters_from_json(Path(config.BASE_CHAPTERS))
    curr_chapter, curr_subchapter = 0, 0
    inside_chapter = False

    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "":
            continue

        matched = False
        if stripped.startswith("##") or stripped[0].isnumeric():
            for _, (ch_num, sub_num) in traverse_chapters(chapters):
                if ch_num < curr_chapter:  # TODO can this happen
                    continue

                ## Match regex with a number of allowed errors
                pattern = regex.compile(
                    f"({build_chapter_regex(chapters, ch_num, sub_num)}){{e<={config.MAX_DEVIATION}}}",
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
            chapter.content += "\n" + stripped

    return chapters
