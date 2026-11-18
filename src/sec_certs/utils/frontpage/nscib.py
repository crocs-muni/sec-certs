from __future__ import annotations

import re
from collections.abc import Iterator
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

_TITLE_ANCHORS = ("Certification Report", "Assurance Continuity Maintenance Report")

_TITLE_RE = re.compile(rf"^(?:[A-Za-z]+ )?(?:{'|'.join(_TITLE_ANCHORS)})$")

_LABEL_RE = re.compile(r"^(?P<label>[A-Za-z][A-Za-z ()]{2,30}?)\s*:\s*(?P<value>.*)$")

_FRONTPAGE_LABELS: dict[str, tuple[str, ...]] = {
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

_ORGANIZATION_TAGS = frozenset(
    {constants.TAG_DEVELOPER, constants.TAG_SPONSOR, constants.TAG_CERT_LAB, constants.TAG_EVAL_FACILITY}
)

_ORGANIZATION_RE = re.compile(rf"^(?P<name>.{{2,80}}?{_LEGAL_FORM_SUFFIX})(?=[\s,]|$)")


def _known_label(block: str) -> tuple[str, str] | None:
    match = _LABEL_RE.match(block)
    if match is None:
        return None
    label = match.group("label").strip().casefold()
    return (label, match.group("value").strip()) if label in _FRONTPAGE_LABELS else None


def _value_below(blocks: list[str], idx: int) -> str:
    below = blocks[idx + 1] if idx + 1 < len(blocks) else ""
    return "" if _LABEL_RE.match(below) else below


def _organization_of(value: str) -> str:
    match = _ORGANIZATION_RE.match(value)
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


def _tagged_values(label: str, value: str) -> Iterator[tuple[str, str]]:
    for tag in _FRONTPAGE_LABELS[label]:
        yield tag, _clean_identity(_organization_of(value) if tag in _ORGANIZATION_TAGS else value)


def _labelled_fields(body: list[str], first_label: int) -> dict[str, Any]:
    items_found: dict[str, Any] = {}
    for idx in range(first_label, len(body)):
        labelled = _known_label(body[idx])
        if labelled is None:
            continue

        label, value = labelled
        value = value or _value_below(body, idx)
        if not value:
            continue

        for tag, tagged_value in _tagged_values(label, value):
            items_found.setdefault(tag, tagged_value)
    return items_found


class NSCIBFrontpageParser(FrontpageParser):
    scheme = "NL"

    def parse_structured(self, document: dict[str, Any]) -> dict[str, Any]:
        return self._parse_blocks(_page_one_blocks(document))

    def parse_text(self, text: str, text_with_newlines: str) -> dict[str, Any]:
        return self._parse_blocks(_page_one_lines(text_with_newlines))

    def _parse_blocks(self, blocks: list[str]) -> dict[str, Any]:
        blocks = _clean_blocks(blocks)

        title = next((idx for idx, block in enumerate(blocks) if _TITLE_RE.match(block)), None)
        if title is None:
            return {}
        body = blocks[title + 1 :]

        first_label = next((idx for idx, block in enumerate(body) if _known_label(block) is not None), len(body))
        items_found = _labelled_fields(body, first_label)

        if constants.TAG_CERT_ID not in items_found:
            cert_id = self._recover_cert_id(" ".join(blocks))
            if cert_id:
                items_found[constants.TAG_CERT_ID] = cert_id

        if first_label > 0:
            items_found[constants.TAG_CERT_ITEM] = _clean_identity(" ".join(body[:first_label]))

        return items_found
