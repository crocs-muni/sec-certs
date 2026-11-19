from __future__ import annotations

import re
from typing import Any

from sec_certs import constants
from sec_certs.utils.frontpage.base import (
    _HYPHEN_BREAK_RE,
    _LEGAL_FORM_SUFFIX,
    FrontpageParser,
    _clean_blocks,
    _clean_identity,
    _page_one_blocks,
    _page_one_lines,
)

# A running header ("Emerson Secure KVM Validation Report, Version 1.0") may precede the title, so the last match counts
_VALIDATION_TITLE_RE = re.compile(r"(?i:Validation Report(?:\s+for(?:\s+the)?)?)(?=\s|$)(?!\s+Page\b)")
_MAINTENANCE_TITLE_RE = re.compile(r"(?i:Assurance Continuity Maintenance Report\s+for)\b[\s_]*")
_PRODUCT_LABEL_RE = re.compile(r"\bProduct\s*:\s*")
_PRODUCT_END_RE = re.compile(r"\b(?:Maintenance )?Report Number\s*:|\bEAL\s*:|\bDate of Activity\s*:")
# Maintenance reports have no report version; the "version" after the product belongs to a referenced document
_MAINTENANCE_REPORT_RE = re.compile(r"(?i:Assurance Continuity Maintenance Report)")

# Not calendar.month_name, which follows the process locale
_MONTH = "January|February|March|April|May|June|July|August|September|October|November|December"
_DATE_RE = re.compile(
    rf"(?i:(?:{_MONTH})\s*\d{{1,2}},?\s*\d{{4}}|\d{{1,2}}\s+(?:{_MONTH}),?\s+\d{{4}}|(?:{_MONTH})\s+\d{{4}})"
    r"|\b\d{1,2}/\d{1,2}/\d{2,4}\b|\b\d{4}-\d{2}-\d{2}\b"
)
_REPORT_VERSION_RE = re.compile(r"(?i:\bVersion):?\s*(\d+(?:\.\d+)*)\b")

# 2011-2018 covers print the vendor and its postal address before the product: "Cisco Systems, Inc, 170 West ... CA 95134"
_STREET_START = r"\d{1,5}\s+[A-Z][\w.'-]*"
_POSTAL_END = r"(?:[A-Z]{2}\s?\d{5}(?:-\d{4})?|[A-Z][a-z]+\s\d{5}|\d{3}-\d{3}|[A-Z]\d[A-Z]\s\d[A-Z]\d|Korea|USA)"
_VENDOR_ADDRESS_RE = re.compile(
    rf"(?P<developer>.{{3,80}}?),?\s+{_STREET_START}.*?\b{_POSTAL_END}(?:,?\s+(?:Korea|USA))?\s+(?P<product>\S.*)"
)

_VENDOR_LINE_RE = re.compile(rf"(?P<developer>\S(?:\S*\s?){{1,6}}?{_LEGAL_FORM_SUFFIX}),?\s+(?P<product>\S.*)")

# OCR reads the NIAP logo above the product as noise ending in its trademark: "Yoyo ome Co, @, S Yonepe> TM"
_LOGO_END_RE = re.compile(r"^.*(?:^|\s)TM(?:\s|$)")

_MAINTENANCE_UPDATE_RE = re.compile(r"\s*\bMaintenance Update of\b.*")
_REPEATED_RE = re.compile(r"(?P<once>.+?)\s+(?P=once)")


def _without_repetition(product: str) -> str:
    product = _MAINTENANCE_UPDATE_RE.sub("", product).strip()
    repeated = _REPEATED_RE.fullmatch(product)
    return repeated.group("once") if repeated else product


_SCHEME_HEADER_RE = re.compile(r"Evaluation and Validation Scheme$")
_LOGO_MARKS = frozenset({"®", "TM"})


def _restore_line_layout(blocks: list[str]) -> list[str]:
    """Docling can lift the product's first line above the title and merge the vendor into the title heading."""
    header = next((idx for idx, block in enumerate(blocks) if _SCHEME_HEADER_RE.search(block)), None)
    if header is None:
        return blocks
    headings = ((idx, _VALIDATION_TITLE_RE.match(blocks[idx])) for idx in range(header + 1, len(blocks)))
    title, heading = next(((idx, match) for idx, match in headings if match), (len(blocks), None))
    if heading is None:
        return blocks
    lifted = [block for block in blocks[header + 1 : title] if block not in _LOGO_MARKS]
    if not lifted:
        return blocks

    after_title = blocks[title][heading.end() :].strip()
    vendor = _VENDOR_LINE_RE.fullmatch(after_title)
    below = [vendor["developer"], *lifted, vendor["product"]] if vendor else [*lifted, after_title]
    return [*blocks[: header + 1], heading.group(), *below, *blocks[title + 1 :]]


class NIAPFrontpageParser(FrontpageParser):
    certification_body = "US NIAP"
    scheme = "US"

    def parse_structured(self, document: dict[str, Any]) -> dict[str, Any]:
        return self._parse(_restore_line_layout(_clean_blocks(_page_one_blocks(document))))

    def parse_text(self, text: str, text_with_newlines: str) -> dict[str, Any]:
        return self._parse(_page_one_lines(text_with_newlines))

    def _parse(self, blocks: list[str]) -> dict[str, Any]:
        text = _HYPHEN_BREAK_RE.sub("-", " ".join(_clean_blocks(blocks)))
        cert_id = self._recover_cert_id(text)
        title_end = self._title_end(text)
        if not cert_id and title_end is None:
            return {}

        items_found: dict[str, Any] = {constants.TAG_CERT_LAB: self.certification_body}
        if cert_id:
            items_found[constants.TAG_CERT_ID] = cert_id

        if title_end is None:
            return items_found

        product_end = self._product_end(text, title_end)
        if product_end is None:
            return items_found

        developer, product = self._developer_and_product(text[title_end:product_end])
        if developer:
            items_found[constants.TAG_DEVELOPER] = developer
        if product:
            items_found[constants.TAG_CERT_ITEM] = product

        date = _DATE_RE.search(text, product_end)
        if date:
            items_found[constants.TAG_REPORT_DATE] = date.group()

        report_version = _REPORT_VERSION_RE.search(text, product_end)
        if report_version and not _MAINTENANCE_REPORT_RE.search(text):
            items_found[constants.TAG_REPORT_VERSION] = report_version.group(1)
        return items_found

    @staticmethod
    def _title_end(text: str) -> int | None:
        end = _PRODUCT_END_RE.search(text)
        head = text[: end.start()] if end else text
        titles = [
            *_MAINTENANCE_TITLE_RE.finditer(head),
            *_VALIDATION_TITLE_RE.finditer(head),
            *_PRODUCT_LABEL_RE.finditer(head),
        ]
        return max((title.end() for title in titles), default=None)

    def _product_end(self, text: str, title_end: int) -> int | None:
        """The product name runs up to the report number label, or to the id when the label is missing."""
        after_title = text[title_end:]
        matches = [*self._cert_id_matches(after_title), _PRODUCT_END_RE.search(after_title)]
        starts = [match.start() for match in matches if match]
        return title_end + min(starts) if starts else None

    @staticmethod
    def _developer_and_product(block: str) -> tuple[str, str]:
        block = _clean_identity(_LOGO_END_RE.sub("", block).strip(" _"))
        vendor = _VENDOR_ADDRESS_RE.fullmatch(block) or _VENDOR_LINE_RE.fullmatch(block)
        if vendor:
            return _clean_identity(vendor.group("developer")), _without_repetition(vendor.group("product"))
        return "", _without_repetition(block)
