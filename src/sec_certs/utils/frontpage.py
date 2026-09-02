from __future__ import annotations

import html
import json
import logging
import re
from abc import ABC, abstractmethod
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


class FrontpageParser(ABC):
    """Base class for scheme-specific certification report frontpage parsers."""

    certification_body: str

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


class NSCIBFrontpageParser(FrontpageParser):
    """
    Frontpage parser for the Dutch scheme (NSCIB).
    """

    certification_body = "NSCIB"

    TITLE_ANCHORS = ("Certification Report", "Assurance Continuity Maintenance Report")

    FRONTPAGE_LABELS: dict[str, tuple[str, ...]] = {
        "sponsor and developer": (constants.TAG_SPONSOR, constants.TAG_DEVELOPER),
        "sponsor": (constants.TAG_SPONSOR,),
        "developer": (constants.TAG_DEVELOPER,),
        "evaluation facility": (constants.TAG_CERT_LAB, constants.TAG_EVAL_FACILITY),
        "report number": (constants.TAG_CERT_ID,),
        "report version": (constants.TAG_REPORT_VERSION,),
        "project number": (constants.TAG_PROJECT_NUMBER,),
        "author(s)": (constants.TAG_AUTHOR,),
        "authors": (constants.TAG_AUTHOR,),
        "author": (constants.TAG_AUTHOR,),
        "date": (constants.TAG_REPORT_DATE,),
    }

    _LABEL_RE = re.compile(r"^(?P<label>[A-Za-z][A-Za-z ()]{2,30}?)\s*:\s*(?P<value>.*)$")

    _ORGANISATION_RE = re.compile(
        r"^(?P<name>.{2,80}?[\s,](?:Inc|Ltd|Limited|B\.?V|N\.?V|GmbH|AG|S\.r\.l|S\.p\.A|S\.A|LLC|Corp"
        r"|Corporation|Co|Oy|Oyj|AB|A/S|ApS|Kft|Zrt|Ltda|SARL|SAS|Pty\sLtd|Sdn\sBhd|K\.K|Pte\.?\sLtd"
        r"|(?i:d\.o\.o|d\.d|s\.r\.o|a\.s|sp\.\sz\so\.o))\.?)(?=\s|$)"
    )

    _HOUSE_NUMBER_RE = re.compile(r"\b\d+\b")

    _ORGANISATION_TAGS = frozenset(
        {constants.TAG_DEVELOPER, constants.TAG_SPONSOR, constants.TAG_CERT_LAB, constants.TAG_EVAL_FACILITY}
    )

    def parse_structured(self, document: dict[str, Any]) -> dict[str, Any]:
        return self._parse_frontpage_blocks(self._page_one_blocks(document))

    def parse_text(self, text: str, text_with_newlines: str) -> dict[str, Any]:
        return self._parse_frontpage_blocks(self._page_one_lines(text_with_newlines))

    @staticmethod
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

    @staticmethod
    def _page_one_lines(text_with_newlines: str) -> list[str]:
        """Split page one into one block per non-blank line, mirroring one Docling text block each."""
        page_one = text_with_newlines.split("\f")[0]

        return [line.strip() for line in page_one.splitlines() if line.strip()]

    def _parse_frontpage_blocks(self, blocks: list[str]) -> dict[str, Any]:
        """Read the label/value form on page one."""
        blocks = self._clean_blocks(blocks)

        body = self._blocks_after_title(blocks)
        if body is None:
            return {}

        items_found, product_name_blocks = self._collect_fields(body)

        if constants.TAG_CERT_ID not in items_found:
            cert_id = self._recover_cert_id(" ".join(blocks))
            if not cert_id:
                return {}
            items_found[constants.TAG_CERT_ID] = cert_id

        if product_name_blocks:
            items_found[constants.TAG_CERT_ITEM] = _clean_identity(" ".join(product_name_blocks))

        return items_found

    @staticmethod
    def _clean_blocks(blocks: list[str]) -> list[str]:
        cleaned = (_clean(block) for block in blocks)
        return [block for block in cleaned if block]

    def _blocks_after_title(self, blocks: list[str]) -> list[str] | None:
        """Return the blocks following the title line, or None if this isn't an NSCIB frontpage."""
        for idx, block in enumerate(blocks):
            if block in self.TITLE_ANCHORS:
                return blocks[idx + 1 :]
        return None

    def _collect_fields(self, blocks: list[str]) -> tuple[dict[str, Any], list[str]]:
        """Split the blocks following the title into recognized label values and product-name lines."""
        items_found: dict[str, Any] = {}
        product_name_blocks: list[str] = []
        seen_label = False

        for idx, block in enumerate(blocks):
            labelled = self._label_of(block)
            if labelled is None:
                if not seen_label:
                    product_name_blocks.append(block)
                continue

            seen_label = True
            label, match = labelled
            for tag, value in self._values_at(blocks, idx, label, match):
                items_found.setdefault(tag, value)

        return items_found, product_name_blocks

    def _label_of(self, block: str) -> tuple[str, re.Match[str]] | None:
        """Return the known frontpage label of ``block`` with its match, or None if it carries none."""
        match = self._LABEL_RE.match(block)
        if match is None:
            return None
        label = match.group("label").strip().casefold()
        return (label, match) if label in self.FRONTPAGE_LABELS else None

    def _values_at(self, blocks: list[str], idx: int, label: str, match: re.Match[str]) -> list[tuple[str, str]]:
        """
        Resolve the tag/value pair(s) for the label matched at ``blocks[idx]``.

        pdftotext keeps the value on the label's own line (``match``). Docling puts it in the
        following block instead, sometimes with the organization's postal address merged in, which
        is trimmed off so that both converters agree.
        """
        value = match.group("value").strip()
        address_merged = False

        if not value:
            nxt = blocks[idx + 1] if idx + 1 < len(blocks) else ""
            if not nxt or self._LABEL_RE.match(nxt):
                return []
            value, address_merged = nxt, True

        resolved = []
        for tag in self.FRONTPAGE_LABELS[label]:
            trimmed = self._organisation_of(value) if address_merged and tag in self._ORGANISATION_TAGS else value
            resolved.append((tag, _clean_identity(trimmed)))
        return resolved

    @classmethod
    def _organisation_of(cls, value: str) -> str:
        """Cut a merged ``<organization> <postal address>`` block down to the organization."""
        match = cls._ORGANISATION_RE.match(value)
        if match:
            return match.group("name")

        number = cls._HOUSE_NUMBER_RE.search(value)
        if not number:
            return value

        # Drop the street name that precedes the house number along with everything after it.
        words = value[: number.start()].split()
        return " ".join(words[:-1]) if len(words) > 1 else value

    @staticmethod
    def _recover_cert_id(text: str) -> str:
        """Find the report number anywhere on the page, using the scheme's canonical id rules."""
        for rule in rules["cc_cert_id"]["NL"]:
            match = re.search(rule, text)
            if match:
                return _clean_identity(match.group())
        return ""


scheme_frontpage_parsers: dict[str, FrontpageParser] = {
    "NL": NSCIBFrontpageParser(),
}
