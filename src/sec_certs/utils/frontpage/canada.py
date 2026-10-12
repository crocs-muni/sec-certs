from __future__ import annotations

import calendar
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


class CanadaFrontpageParser(FrontpageParser):
    """
    Frontpage parser for the Canadian scheme.
    """

    certification_body = "CANADA"
    scheme = "CA"

    _TITLE_RE = re.compile(r"COMMON CRITERIA\s+CERTIFICATION REPORT(?:\s+[A-Z][A-Z]+(?:\s+[A-Z][A-Z]+)*)?")
    _MONTHS = "|".join(calendar.month_name[1:])
    _DATE_RE = re.compile(rf"\b\d{{1,2}}\s+(?:{_MONTHS})\s+\d{{4}}\b")

    def parse_structured(self, document: dict[str, Any]) -> dict[str, Any]:
        return self._parse(_page_one_blocks(document))

    def parse_text(self, text: str, text_with_newlines: str) -> dict[str, Any]:
        return self._parse(_page_one_lines(text_with_newlines))

    def _parse(self, blocks: list[str]) -> dict[str, Any]:
        full_text = " ".join(_clean_blocks(blocks))

        cert_id = self._recover_cert_id(full_text)
        if not cert_id:
            return {}

        items_found: dict[str, Any] = {
            constants.TAG_CERT_ID: cert_id,
            constants.TAG_CERT_LAB: self.certification_body,
        }
        items_found.update(self._fields_after_title(full_text))

        return items_found

    def _fields_after_title(self, full_text: str) -> dict[str, Any]:
        """Recover the product name and date, which both sit right after the frontpage title."""
        title_match = self._TITLE_RE.search(full_text)
        if title_match is None:
            return {}

        rest = full_text[title_match.end() :].strip()
        fields: dict[str, Any] = {}

        date_match = self._DATE_RE.search(rest)
        if date_match:
            fields[constants.TAG_REPORT_DATE] = date_match.group()

        cert_item = self._recover_cert_item(rest, date_match)
        if cert_item:
            fields[constants.TAG_CERT_ITEM] = cert_item

        return fields

    def _recover_cert_item(self, rest: str, date_match: re.Match[str] | None) -> str:
        product_name_end_candidates = [match.start() for match in self._cert_id_matches(rest)]
        if date_match:
            product_name_end_candidates.append(date_match.start())

        product_name_end = min(product_name_end_candidates) if product_name_end_candidates else len(rest)
        return _clean_identity(rest[:product_name_end])
