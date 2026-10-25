"""
Shared code for the scheme-specific certification report frontpage parsers.

Every report reaches a parser in up to two renderings: the serialized Docling document, in which
page one is a list of text blocks, and the pdftotext output, in which page one is the text before
the first form feed. A parser implements both `parse_structured` and `parse_text`; `parse` tries the
structured rendering first and falls back to the text one.
"""

from __future__ import annotations

import html
import json
import logging
import re
from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from sec_certs import constants
from sec_certs.cert_rules import rules
from sec_certs.utils.extract import load_text_file, normalize_match_string

logger = logging.getLogger(__name__)

_DOCLING_FURNITURE_LABELS = frozenset({"page_header", "page_footer"})

_MARKDOWN_HEADING_RE = re.compile(r"(?:^|(?<=\s))#{1,6}\s*")
_BULLET_CHARS = "●•*-–— \t"

# Converters sometimes break a hyphenated identifier across lines ("NSCIB- 2400046-01").
_HYPHEN_BREAK_RE = re.compile(r"(?<=\w)-\s+(?=\w)")

_LEGAL_FORM = (
    r"(?:Inc|Ltd|Limited|B\.?V|N\.?V|GmbH|AG|S\.r\.l|S\.p\.A|S\.A|LLC|Corp"
    r"|Corporation|Co|Oy|Oyj|AB|A/S|ApS|Kft|Zrt|Ltda|SARL|SAS|Pty\sLtd|Sdn\sBhd|K\.K|Pte\.?\sLtd"
    r"|(?i:d\.o\.o|d\.d|s\.r\.o|a\.s|sp\.\sz\so\.o))"
)


def _clean(value: str) -> str:
    """Flatten a block to one line of printable text, free of Markdown headings and bullets."""
    value = html.unescape(value.replace("\n", " "))
    value = _MARKDOWN_HEADING_RE.sub("", value)
    value = value.strip().lstrip(_BULLET_CHARS)
    value = re.sub(r"\s{2,}", " ", value).strip()
    return "".join(filter(str.isprintable, value))


def _clean_blocks(blocks: list[str]) -> list[str]:
    """Clean every block and drop those that come out empty."""
    cleaned = (_clean(block) for block in blocks)
    return [block for block in cleaned if block]


def _clean_identity(value: str) -> str:
    """Clean a value that names something (a product, an organization, a certificate id)."""
    value = _HYPHEN_BREAK_RE.sub("-", _clean(value))
    return normalize_match_string(value)


def _is_page_one_content(block: dict[str, Any]) -> bool:
    """Whether a Docling text block holds page-one content rather than furniture or a later page."""
    if block.get("label") in _DOCLING_FURNITURE_LABELS or not block.get("text"):
        return False
    prov = block.get("prov") or []
    return not prov or prov[0].get("page_no") == 1


def _page_one_blocks(document: dict[str, Any]) -> list[str]:
    """The raw text of page one of a Docling document, one entry per text block."""
    return [block["text"] for block in document.get("texts", []) if _is_page_one_content(block)]


def _page_one_lines(text_with_newlines: str) -> list[str]:
    """Split page one into one block per non-blank line, mirroring one Docling text block each."""
    page_one = text_with_newlines.split("\f")[0]
    return [line.strip() for line in page_one.splitlines() if line.strip()]


class FrontpageParser(ABC):
    scheme: str

    def parse(self, txt_path: Path, json_path: Path | None = None) -> dict[str, Any]:
        """
        Extract the frontpage fields.

        :param txt_path: Path to the text rendering of the report.
        :param json_path: Path to the serialized docling document, if the converter produced one.
        :return: The extracted fields, empty if nothing could be extracted.
        :raises ValueError: If parsing fails unexpectedly.
        """
        if json_path is not None and json_path.exists():
            items_found = self._parse_structured_file(json_path)
            if items_found:
                items_found[constants.TAG_PARSE_STRATEGY] = "structured"
                return items_found

        items_found = self._parse_text_file(txt_path)
        if items_found:
            items_found[constants.TAG_PARSE_STRATEGY] = "text"
        else:
            logger.error(f"Front page not found for file: {txt_path}")
        return items_found

    @abstractmethod
    def parse_structured(self, document: dict[str, Any]) -> dict[str, Any]:
        """
        Extract the frontpage fields from a serialized docling document.

        :param document: The deserialized docling JSON.
        :return: The extracted fields, empty if nothing could be extracted.
        """

    @abstractmethod
    def parse_text(self, text: str, text_with_newlines: str) -> dict[str, Any]:
        """
        Extract the frontpage fields from the textual rendering of the report.

        :param text: The document with newlines replaced by spaces.
        :param text_with_newlines: The document with newlines preserved.
        :return: The extracted fields, empty if nothing could be extracted.
        """

    def _parse_structured_file(self, json_path: Path) -> dict[str, Any]:
        try:
            with json_path.open("r", encoding="utf-8") as handle:
                document = json.load(handle)
            items_found = self.parse_structured(document)
        except Exception as e:
            logger.warning(f"Structured frontpage parsing failed for {json_path}: {e}, falling back to text.")
            return {}

        if not items_found:
            logger.warning(f"Structured frontpage parsing yielded nothing for {json_path}, falling back to text.")
        return items_found

    def _parse_text_file(self, txt_path: Path) -> dict[str, Any]:
        try:
            text, text_with_newlines, _ = load_text_file(txt_path)
            return self.parse_text(text, text_with_newlines)
        except Exception as e:
            relative_filepath = Path(*txt_path.parts[-4:])
            error_msg = f"Failed to parse {type(self).__name__} headers from frontpage: {relative_filepath}; {e}"
            logger.error(error_msg)
            raise ValueError(error_msg) from e

    def _cert_id_matches(self, text: str) -> Iterator[re.Match[str]]:
        """Yield the first match of each of the scheme's certificate id rules, in rule order."""
        for rule in rules["cc_cert_id"][self.scheme]:
            match = re.search(rule, text)
            if match:
                yield match

    def _recover_cert_id(self, text: str) -> str:
        """The scheme's certificate id as it appears in the text, or "" when none does."""
        match = next(self._cert_id_matches(text), None)
        return _clean_identity(match.group()) if match else ""
