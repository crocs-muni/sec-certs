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

SAR_CLASSES = {x for x in SAR_CLASS_MAPPING}
SAR_DICT_KEY = "rules_security_assurance_components"


@dataclass(frozen=True, eq=True)
class SAR(ComplexSerializableType):
    assurance_class: str
    family: str
    level: int

    @classmethod
    def from_string(cls, string):
        assurance_class = SAR_CLASS_MAPPING.get(string.split("_")[0], None)
        family = string.split(".")[0]
        level = int(string.split(".")[1])
        return cls(assurance_class, family, level)

    @staticmethod
    def is_correctly_formatted(string):
        if len(string.split(".")) == 1:
            return False
        return True

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, SAR):
            raise ValueError(f"cannot compare {type(other)} with SAR.")
        return str(self) < str(other)
