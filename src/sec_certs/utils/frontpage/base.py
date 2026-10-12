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

# Docling labels that carry running headers/footers rather than page content.
_DOCLING_FURNITURE_LABELS = frozenset({"page_header", "page_footer"})

_MARKDOWN_HEADING_RE = re.compile(r"(?:^|(?<=\s))#{1,6}\s*")
_HYPHEN_BREAK_RE = re.compile(r"(?<=\w)-\s+(?=\w)")
_BULLET_CHARS = "●•*-–— \t"


def _clean(value: str) -> str:
    """Normalize a block of extracted text."""
    value = html.unescape(value.replace("\n", " "))
    value = _MARKDOWN_HEADING_RE.sub("", value)
    value = value.strip().lstrip(_BULLET_CHARS)
    value = re.sub(r"\s{2,}", " ", value).strip()
    return "".join(filter(str.isprintable, value))


def _clean_identity(value: str) -> str:
    """Normalize a frontpage identity value (certificate id, certified item, developer)."""
    # Converters sometimes break a hyphenated identifier across lines ("NSCIB- 2400046-01"); rejoin
    value = _HYPHEN_BREAK_RE.sub("-", _clean(value))
    return normalize_match_string(value)


def _page_one_blocks(document: dict[str, Any]) -> list[str]:
    """Keep page-one Docling blocks, dropping running headers/footers and empty blocks."""
    blocks = []
    for block in document.get("texts", []):
        if block.get("label") in _DOCLING_FURNITURE_LABELS or not block.get("text"):
            continue
        prov = block.get("prov") or []
        if prov and prov[0].get("page_no") != 1:
            continue
        blocks.append(block["text"])
    return blocks


def _page_one_lines(text_with_newlines: str) -> list[str]:
    """Split page one into one block per non-blank line, mirroring one Docling text block each."""
    page_one = text_with_newlines.split("\f")[0]
    return [line.strip() for line in page_one.splitlines() if line.strip()]


class FrontpageParser(ABC):
    """Base class for scheme-specific certification report frontpage parsers."""

    certification_body: str
    # Key of the scheme's canonical certificate id rules in `rules["cc_cert_id"]`.
    scheme: str

    @abstractmethod
    def parse_structured(self, document: dict[str, Any]) -> dict[str, Any]:
        """
        Extract the frontpage fields from a serialized docling document.

        :param document: The deserialized docling JSON.
        :return: The extracted fields, empty if nothing could be extracted.
        """
        raise NotImplementedError("Not meant to be implemented by the base class.")

    @abstractmethod
    def parse_text(self, text: str, text_with_newlines: str) -> dict[str, Any]:
        """
        Extract the frontpage fields from the textual rendering of the report.

        :param text: The document with newlines replaced by spaces.
        :param text_with_newlines: The document with newlines preserved.
        :return: The extracted fields, empty if nothing could be extracted.
        """
        raise NotImplementedError("Not meant to be implemented by the base class.")

    def _cert_id_matches(self, text: str) -> Iterator[re.Match[str]]:
        """Yield the first match of each of the scheme's certificate id rules, in rule order."""
        for rule in rules["cc_cert_id"][self.scheme]:
            match = re.search(rule, text)
            if match:
                yield match

    def _recover_cert_id(self, text: str) -> str:
        """Find the certificate id anywhere in ``text``, using the scheme's canonical id rules."""
        match = next(self._cert_id_matches(text), None)
        return _clean_identity(match.group()) if match else ""

    def parse(self, txt_path: Path, json_path: Path | None = None) -> dict[str, Any]:
        """
        Extract the frontpage fields, preferring the structured document when one is available.

        :param txt_path: Path to the text rendering of the report.
        :param json_path: Path to the serialized docling document, if the converter produced one.
        :return: The extracted fields, empty if nothing could be extracted.
        :raises ValueError: If parsing fails unexpectedly.
        """
        if json_path is not None and json_path.exists():
            try:
                with json_path.open("r", encoding="utf-8") as handle:
                    document = json.load(handle)
                items_found = self.parse_structured(document)
                if items_found:
                    items_found[constants.TAG_PARSE_STRATEGY] = "structured"
                    return items_found
                logger.warning(f"Structured frontpage parsing yielded nothing for {json_path}, falling back to text")
            except Exception as e:
                logger.warning(f"Structured frontpage parsing failed for {json_path}: {e}, falling back to text")

        try:
            text, text_with_newlines, _ = load_text_file(txt_path)
            items_found = self.parse_text(text, text_with_newlines)
        except Exception as e:
            relative_filepath = "/".join(str(txt_path).split("/")[-4:])
            error_msg = f"Failed to parse {type(self).__name__} headers from frontpage: {relative_filepath}; {e}"
            logger.error(error_msg)
            raise ValueError(error_msg) from e

        if items_found:
            items_found[constants.TAG_PARSE_STRATEGY] = "text"
        else:
            logger.error(f"ERROR: front page not found for file: {txt_path}")
        return items_found
