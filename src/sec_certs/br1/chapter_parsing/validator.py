import logging
from typing import List, Tuple

from sec_certs.br1.models.chapter import Chapter

logger = logging.getLogger(__name__)


def validate_chapters(chapters: List[Chapter]) -> Tuple[int, int]:
    """
    The function counts warnings and errors and displays logs.
    error: The number of non-optional chapters or subchapters that
    failed validation (i.e., missing, empty, or not found).
    warning: The total number of subchapters (including optional ones)
    that had no content or were not found. This is purely informational and
    does not necessarily mean a failure occurred.
    """
    count, error = 0, 0

    for i, chapter in enumerate(chapters, 1):
        if not chapter.found:
            logger.debug(f"Chapter not found {i}!")
            error += 1
        for j, sub in enumerate(chapter.subchapters, 1):
            if not sub.content or not sub.found:
                count += 1
                msg = f"Subchapter number {str(i)}.{str(j)} has no content / not found."
                logger.debug(msg if not sub.optional else f"Optional {msg}")
                if not sub.optional:
                    error += 1
    logger.debug(f"Total empty subchapters: {count}")
    return error, count
