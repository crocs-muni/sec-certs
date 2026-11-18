from __future__ import annotations

import re
from typing import Any

from sec_certs import constants
from sec_certs.utils.frontpage.base import (
    _LEGAL_FORM_SUFFIX,
    FrontpageParser,
    _clean_blocks,
    _clean_identity,
    _page_one_blocks,
    _page_one_lines,
)

# Only the banner Docling merges in may follow the title, or an all-caps product name ("BIG-IP") gets eaten
_CURRENT_TITLE = r"COMMON CRITERIA\s+CERTIFICATION REPORT(?:\s+CANADIAN CENTRE FOR CYBER SECURITY)?"
_LEGACY_TITLE = r"Certification Report(?:\s+\S+(?:\s+\S+){0,4}?\s+[Ee]valuation\s+of\b)?"
_CURRENT_TITLE_RE = re.compile(_CURRENT_TITLE)
_TITLE_RE = re.compile(rf"{_CURRENT_TITLE}|{_LEGACY_TITLE}")

# Not calendar.month_name, which follows the process locale
_MONTHS = "January|February|March|April|May|June|July|August|September|October|November|December"
_DATE_RE = re.compile(rf"\b\d{{1,2}}\s+(?:{_MONTHS})\s+\d{{4}}\b")
_ISSUED_BY_RE = re.compile(r"\bIssued by\b")
_DETACHED_MARK_RE = re.compile(r"\s+(?=[®™])")
_LEGAL_FORM_END_RE = re.compile(rf"{_LEGAL_FORM_SUFFIX}$")
_REPORT_VERSION_RE = re.compile(r"(?<!\S)[Vv]?(\d+\.\d+)(?!\S)")


def _words(value: str) -> list[str]:
    return [re.sub(r"\W", "", word).casefold() for word in value.split()]


def _names_developer(line: str, product: str) -> bool:
    """A developer line ends in a legal form ("Fortinet, Inc.") or opens the product name ("Dell EMC")."""
    if _LEGAL_FORM_END_RE.search(line):
        return True
    words = _words(line)
    return bool(words) and words == _words(product)[: len(words)]


class CanadaFrontpageParser(FrontpageParser):
    certification_body = "CANADA"
    scheme = "CA"

    def parse_structured(self, document: dict[str, Any]) -> dict[str, Any]:
        return self._parse(_clean_blocks(_page_one_blocks(document)))

    def parse_text(self, text: str, text_with_newlines: str) -> dict[str, Any]:
        return self._parse(_clean_blocks(_page_one_lines(text_with_newlines)))

    def _developer_index(self, blocks: list[str]) -> int | None:
        """The 2020 template puts the developer on its own line between the product name and the date or cert id."""
        title = next((idx for idx, block in enumerate(blocks) if _CURRENT_TITLE_RE.fullmatch(block)), None)
        if title is None:
            return None

        end = next((idx for idx in range(title + 1, len(blocks)) if self._is_date_or_cert_id(blocks[idx])), None)
        if end is None or end - title < 3:
            return None

        product, developer = " ".join(blocks[title + 1 : end - 1]), blocks[end - 1]
        return end - 1 if _names_developer(developer, product) else None

    def _is_date_or_cert_id(self, block: str) -> bool:
        return _DATE_RE.search(block) is not None or next(self._cert_id_matches(block), None) is not None

    def _parse(self, blocks: list[str]) -> dict[str, Any]:
        developer_index = self._developer_index(blocks)
        developer = blocks.pop(developer_index) if developer_index is not None else None

        text = " ".join(blocks)
        cert_id = self._recover_cert_id(text)
        if not cert_id:
            return {}

        items_found: dict[str, Any] = {
            constants.TAG_CERT_ID: cert_id,
            constants.TAG_CERT_LAB: self.certification_body,
        }

        title = _TITLE_RE.search(text)
        if title is None:
            return items_found

        after_title = text[title.end() :].strip()
        date = _DATE_RE.search(after_title)
        if date:
            items_found[constants.TAG_REPORT_DATE] = date.group()

        product_name_end = self._product_name_end(after_title, date)
        product_name = _clean_identity(_DETACHED_MARK_RE.sub("", after_title[:product_name_end]))
        if product_name:
            items_found[constants.TAG_CERT_ITEM] = product_name
        if developer:
            items_found[constants.TAG_DEVELOPER] = _clean_identity(developer)

        report_version = _REPORT_VERSION_RE.search(after_title, product_name_end)
        if report_version:
            items_found[constants.TAG_REPORT_VERSION] = report_version.group(1)
        return items_found

    def _product_name_end(self, after_title: str, date: re.Match[str] | None) -> int:
        """The product name runs up to the first cert id, date or "Issued by"."""
        ends = [*self._cert_id_matches(after_title), date, _ISSUED_BY_RE.search(after_title)]
        return min((match.start() for match in ends if match), default=len(after_title))
