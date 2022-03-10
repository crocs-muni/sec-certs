import copy
import logging
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Optional

import sec_certs.helpers as helpers
from sec_certs.serialization.json import ComplexSerializableType

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProtectionProfile(ComplexSerializableType):
    """
    Object for holding protection profiles.
    """

    pp_name: str
    pp_link: Optional[str] = None
    pp_ids: Optional[FrozenSet[str]] = None

    def __post_init__(self):
        super().__setattr__("pp_name", helpers.sanitize_string(self.pp_name))
        super().__setattr__("pp_link", helpers.sanitize_link(self.pp_link))

    @classmethod
    def from_dict(cls, dct: Dict[str, Any]) -> "ProtectionProfile":
        new_dct = copy.deepcopy(dct)
        new_dct["pp_ids"] = frozenset(new_dct["pp_ids"]) if new_dct["pp_ids"] else None
        return cls(*tuple(new_dct.values()))

    @classmethod
    def from_old_api_dict(cls, dct: Dict[str, Any]) -> "ProtectionProfile":
        pp_name = helpers.sanitize_string(dct["csv_scan"]["cc_pp_name"])
        pp_link = helpers.sanitize_link(dct["csv_scan"]["link_pp_document"])
        pp_ids = frozenset(dct["processed"]["cc_pp_csvid"]) if dct["processed"]["cc_pp_csvid"] else None
        return cls(pp_name, pp_link, pp_ids)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ProtectionProfile):
            return False
        return self.pp_name == other.pp_name and self.pp_link == other.pp_link

    def __lt__(self, other: "ProtectionProfile") -> bool:
        return self.pp_name < other.pp_name
