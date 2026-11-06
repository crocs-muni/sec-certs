from __future__ import annotations

import re
from typing import Any

from sec_certs import constants
from sec_certs.utils.frontpage.base import (
    FrontpageParser,
    _clean_blocks,
    _clean_identity,
    _page_one_blocks,
    _page_one_lines,
)

_FOR = frozenset({"for", "zu"})
_FROM = frozenset({"from", "der"})
_SPONSORED_BY = "sponsored by"
_ADMINISTRATION_ID = "administration id"

# Split at the first "from"/"der", as a developer may contain "der"
_MERGED_FRONTPAGE_RE = re.compile(
    r"^(?:(?P<for>for|zu)(?:\s+|$))?(?P<product>.*?)"
    r"(?:(?:^|\s+)(?P<from>from|der)(?:\s+|$)(?P<developer>.*?))?"
    r"(?:(?:^|\s+)(?P<sponsored>sponsored by)(?:\s+|$)(?P<sponsor>.*))?$"
)
_GLUED_CONNECTOR_RE = re.compile(r"^(?:for|zu|from|der|sponsored by)\s|\s(?:from|der)$")

# Titles, the letterhead, recognition logos and the maintenance summary
_BOILERPLATE_RE = re.compile(
    r"^(?:Bundesamt\b|BSI\s+-|Certification Report|Zertifizierungsreport|Assurance Continuity|SOGIS\b"
    r"|Common Criteria\b|The IT product\b|Das in diesem\b)"
)
_GLUED_LOGO_CAPTION_RE = re.compile(r"\s+(?:Common Criteria (?:Recognition|Arrangement)|SOGIS\b)")


def _is_for(block: str) -> bool:
    return block.casefold() in _FOR


def _is_from(block: str) -> bool:
    return block.casefold() in _FROM


def _is_sponsored_by(block: str) -> bool:
    return block.casefold() == _SPONSORED_BY


def _split_at_connectors(block: str) -> list[str]:
    merged = _MERGED_FRONTPAGE_RE.match(block)
    if merged is None:
        return [block]
    parts = (merged.group(name) for name in ("for", "product", "from", "developer", "sponsored", "sponsor"))
    return [part for part in parts if part]


def _lines_from_id(blocks: list[str], id_end: int) -> list[str]:
    id_line, id_tail = blocks[0][:id_end], blocks[0][id_end:].strip()
    if _BOILERPLATE_RE.match(id_tail):
        return [id_line, id_tail, *blocks[1:]]

    lines = [id_line, *_split_at_connectors(id_tail)]
    for idx, block in enumerate(blocks[1:], start=1):
        if _BOILERPLATE_RE.match(block):
            return lines + blocks[idx:]
        lines += _split_at_connectors(block) if _GLUED_CONNECTOR_RE.search(block) else [block]
    return lines


def _with_for_after_id(lines: list[str]) -> list[str]:
    """Docling can move the "for" into the product ("M9900" / "for A21 with ...")."""
    connector = next((idx for idx, line in enumerate(lines) if _is_for(line) or _is_from(line)), None)
    if connector is None or connector <= 1 or _is_from(lines[connector]):
        return lines
    return [lines[0], lines[connector], *lines[1:connector], *lines[connector + 1 :]]


def _product_start(blocks: list[str], id_index: int) -> int:
    start = id_index + 1
    return start + 1 if start < len(blocks) and _is_for(blocks[start]) else start


def _product_span(blocks: list[str], id_index: int) -> tuple[int, int] | None:
    start = _product_start(blocks, id_index)
    end = next((idx for idx in range(start, len(blocks)) if _is_from(blocks[idx])), None)
    return (start, end) if end is not None and end > start else None


class BSIFrontpageParser(FrontpageParser):
    certification_body = "BSI"
    scheme = "DE"

    def parse_structured(self, document: dict[str, Any]) -> dict[str, Any]:
        return self._parse(self._restore_line_layout(_clean_blocks(_page_one_blocks(document))))

    def parse_text(self, text: str, text_with_newlines: str) -> dict[str, Any]:
        return self._parse(_clean_blocks(_page_one_lines(text_with_newlines)))

    def _parse(self, blocks: list[str]) -> dict[str, Any]:
        text = " ".join(blocks)
        items_found: dict[str, Any] = {constants.TAG_CERT_LAB: self.certification_body}
        cert_id = self._recover_cert_id(text)
        if cert_id:
            items_found[constants.TAG_CERT_ID] = cert_id
        eucc_cert_id = self._eucc_cert_id(text)
        if eucc_cert_id:
            items_found[constants.TAG_EUCC_CERT_ID] = eucc_cert_id

        bsi_id = self._locate_bsi_id(blocks)
        if bsi_id is None:
            return items_found

        product_span = _product_span(blocks, bsi_id[0])
        if product_span is None:
            return items_found
        product_start, product_end = product_span
        items_found[constants.TAG_CERT_ITEM] = _clean_identity(" ".join(blocks[product_start:product_end]))

        developer, developer_end = self._value_from(blocks, product_end + 1)
        if developer:
            items_found[constants.TAG_DEVELOPER] = developer

        if developer_end < len(blocks) and _is_sponsored_by(blocks[developer_end]):
            sponsor, _ = self._value_from(blocks, developer_end + 1)
            if sponsor:
                items_found[constants.TAG_SPONSOR] = sponsor
        return items_found

    def _eucc_cert_id(self, text: str) -> str | None:
        """EUCC reports list the EUCC id first and the BSI id below it as the "Administration ID"."""
        match = next((m for m in self._cert_id_matches(text) if m.group().startswith("EUCC")), None)
        return _clean_identity(match.group()) if match else None

    def _locate_bsi_id(self, blocks: list[str]) -> tuple[int, int] | None:
        """The index of the block holding the BSI id and the offset where the id ends in it."""
        for idx, block in enumerate(blocks):
            bsi_id = next((m for m in self._cert_id_matches(block) if m.group().startswith("BSI")), None)
            if bsi_id:
                return idx, bsi_id.end()
        return None

    def _restore_line_layout(self, blocks: list[str]) -> list[str]:
        """Turn Docling's merged and sometimes reordered blocks into the one-line-per-block layout of pdftotext."""
        bsi_id = self._locate_bsi_id(blocks)
        if bsi_id is None:
            return blocks

        id_index, id_end = bsi_id
        above_id = blocks[:id_index]
        lines = _with_for_after_id(_lines_from_id(blocks[id_index:], id_end))

        # A product line Docling placed above the id belongs at the start of the product
        stray_product = [block for block in above_id if not self._belongs_above_id(block)]
        product_start = _product_start(lines, 0)
        return [*above_id, *lines[:product_start], *stray_product, *lines[product_start:]]

    def _value_from(self, blocks: list[str], start: int) -> tuple[str, int]:
        """The value starting at `start` and the index of the block that ends it."""
        values = []
        end = start
        while end < len(blocks) and not self._ends_value(blocks[end]):
            caption = _GLUED_LOGO_CAPTION_RE.search(blocks[end])
            if caption:
                values.append(blocks[end][: caption.start()])
                break
            values.append(blocks[end])
            end += 1
        return _clean_identity(" ".join(values)), end

    def _belongs_above_id(self, block: str) -> bool:
        return self._is_boilerplate(block) or block.casefold().rstrip(":") == _ADMINISTRATION_ID

    def _ends_value(self, block: str) -> bool:
        return self._is_boilerplate(block) or _is_sponsored_by(block)

    def _is_boilerplate(self, block: str) -> bool:
        return _BOILERPLATE_RE.match(block) is not None or next(self._cert_id_matches(block), None) is not None
