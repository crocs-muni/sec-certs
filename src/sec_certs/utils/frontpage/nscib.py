from __future__ import annotations

import re
from typing import Any

from sec_certs import constants
from sec_certs.utils.frontpage.base import (
    _LEGAL_FORM,
    FrontpageParser,
    _clean_blocks,
    _clean_identity,
    _page_one_blocks,
    _page_one_lines,
)


class NSCIBFrontpageParser(FrontpageParser):
    scheme = "NL"

    TITLE_ANCHORS = ("Certification Report", "Assurance Continuity Maintenance Report")

    # Newer reports prefix the title with the scheme ("EUCC Certification Report"). Only a plain
    # word may precede it: anything else is a different line that merely ends with the anchor, such
    # as the reference line "NSCIB-CC-05-6609 Certification Report" of the older report template.
    _TITLE_RE = re.compile(rf"^(?:[A-Za-z]+ )?(?:{'|'.join(TITLE_ANCHORS)})$")

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

    # Comma-chained legal forms belong to the name ("Co., Ltd."); other text after it does not.
    _ORGANISATION_RE = re.compile(rf"^(?P<name>.{{2,80}}?[\s,]{_LEGAL_FORM}\.?(?:,?\s+{_LEGAL_FORM}\.?)*)(?=[\s,]|$)")

    _ORGANISATION_TAGS = frozenset(
        {constants.TAG_DEVELOPER, constants.TAG_SPONSOR, constants.TAG_CERT_LAB, constants.TAG_EVAL_FACILITY}
    )

    def parse_structured(self, document: dict[str, Any]) -> dict[str, Any]:
        return self._parse_frontpage_blocks(_page_one_blocks(document))

    def parse_text(self, text: str, text_with_newlines: str) -> dict[str, Any]:
        return self._parse_frontpage_blocks(_page_one_lines(text_with_newlines))

    def _parse_frontpage_blocks(self, blocks: list[str]) -> dict[str, Any]:
        blocks = _clean_blocks(blocks)

        body = self._blocks_after_title(blocks)
        if body is None:
            return {}

        items_found, product_name_blocks = self._collect_fields(body)

        if constants.TAG_CERT_ID not in items_found:
            cert_id = self._recover_cert_id(" ".join(blocks))
            if cert_id:
                items_found[constants.TAG_CERT_ID] = cert_id

        if product_name_blocks:
            items_found[constants.TAG_CERT_ITEM] = _clean_identity(" ".join(product_name_blocks))

        return items_found

    def _blocks_after_title(self, blocks: list[str]) -> list[str] | None:
        """Return the blocks following the title line, or None if this isn't an NSCIB frontpage."""
        for idx, block in enumerate(blocks):
            if self._TITLE_RE.match(block):
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
        match = self._LABEL_RE.match(block)
        if match is None:
            return None
        label = match.group("label").strip().casefold()
        return (label, match) if label in self.FRONTPAGE_LABELS else None

    def _values_at(self, blocks: list[str], idx: int, label: str, match: re.Match[str]) -> list[tuple[str, str]]:
        """
        pdftotext keeps the value on the label's own line (``match``). Docling emits whole frontpage
        cells instead, before or merged into the label's block, carrying the organization's postal
        address. Organizations are therefore always address-trimmed, a no-op on a bare name, so that
        both converters agree.
        """
        value = match.group("value").strip()

        if not value:
            nxt = blocks[idx + 1] if idx + 1 < len(blocks) else ""
            if not nxt or self._LABEL_RE.match(nxt):
                return []
            value = nxt

        resolved = []
        for tag in self.FRONTPAGE_LABELS[label]:
            trimmed = self._organisation_of(value) if tag in self._ORGANISATION_TAGS else value
            resolved.append((tag, _clean_identity(trimmed)))
        return resolved

    @classmethod
    def _organisation_of(cls, value: str) -> str:
        """Cut a merged ``<organization> <postal address>`` block down to the organization."""
        match = cls._ORGANISATION_RE.match(value)
        if match:
            return match.group("name")

        # No legal form to cut at: the address starts at the street name, which is the word before a
        # standalone house number ("Brassersplein 2") or the word holding a glued one ("Delft1187").
        words = value.split()
        number_index = next((i for i, word in enumerate(words) if any(char.isdigit() for char in word)), None)
        if number_index is None:
            return value

        street_index = number_index - 1 if words[number_index].strip(",.").isdigit() else number_index
        return " ".join(words[:street_index]) if street_index > 0 else value
