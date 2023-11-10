from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from sec_certs.serialization.json import ComplexSerializableType

SAR_CLASS_MAPPING = {
    "APE": "Protection Profile evaluation",
    "ACE": "Protection Profile configuration evaluation",
    "ASE": "Security Target evaluation",
    "ADV": "Development",
    "AGD": "Guidance documents",
    "ALC": "Life-cycle support",
    "ATE": "Tests",
    "AVA": "Vulnerability assessment",
    "ACO": "Comoposition",
}

SAR_CLASSES = set(SAR_CLASS_MAPPING)
SAR_DICT_KEY = "cc_sar"


@dataclass(frozen=True, eq=True)
class SAR(ComplexSerializableType):
    family: str
    level: int

    @property
    def assurance_class(self):
        return SAR_CLASS_MAPPING.get(self.family.split("_")[0], None)

    @classmethod
    def from_string(cls, string: str) -> SAR:
        if not cls.contains_level(string):
            raise ValueError("SAR misses level integer")
        if not cls.matches_re(string):
            raise ValueError("SAR does not match any regular expression")
        family = string.split(".")[0]
        level = int(string.split(".")[1])
        return cls(family, level)

    @staticmethod
    def contains_level(string: str) -> bool:
        if len(string.split(".")) == 1:
            return False
        return True

    @staticmethod
    def matches_re(string: str) -> bool:
        return any(
            re.match(sar_class + "(?:_[A-Z]{3,4}){1,2}(?:\\.[0-9]){0,2}", string) for sar_class in SAR_CLASS_MAPPING
        )

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, SAR):
            raise ValueError(f"cannot compare {type(other)} with SAR.")
        return str(self) < str(other)
