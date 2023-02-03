from __future__ import annotations

import copy
import logging
from dataclasses import dataclass
from typing import Any

from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils import sanitization

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProtectionProfile(ComplexSerializableType):
    """
    Object for holding protection profiles.
    """

    pp_name: str
    pp_eal: str | None
    pp_link: str | None = None
    pp_ids: frozenset[str] | None = None

    def __post_init__(self):
        super().__setattr__("pp_name", sanitization.sanitize_string(self.pp_name))
        super().__setattr__("pp_link", sanitization.sanitize_link(self.pp_link))

    @classmethod
    def from_dict(cls, dct: dict[str, Any]) -> ProtectionProfile:
        new_dct = copy.deepcopy(dct)
        new_dct["pp_ids"] = frozenset(new_dct["pp_ids"]) if new_dct["pp_ids"] else None
        return cls(*tuple(new_dct.values()))

    @classmethod
    def from_old_api_dict(cls, dct: dict[str, Any]) -> ProtectionProfile:
        pp_name = sanitization.sanitize_string(dct["csv_scan"]["cc_pp_name"])
        pp_link = sanitization.sanitize_link(dct["csv_scan"]["link_pp_document"])
        pp_ids = frozenset(dct["processed"]["cc_pp_csvid"]) if dct["processed"]["cc_pp_csvid"] else None
        eal_set = sanitization.sanitize_security_levels(dct["csv_scan"]["cc_security_level"])

        if not len(eal_set) <= 1:
            raise ValueError("EAL field should have single value or should be empty.")

        eal_str = list(eal_set)[0] if eal_set else None

        return cls(pp_name, eal_str, pp_link, pp_ids)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ProtectionProfile):
            return False
        return self.pp_name == other.pp_name and self.pp_link == other.pp_link

    def __lt__(self, other: ProtectionProfile) -> bool:
        return self.pp_name < other.pp_name
