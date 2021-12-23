from dataclasses import dataclass
from datetime import datetime, date
from enum import Enum
from typing import Mapping, Set

from sec_certs.serialization.json import ComplexSerializableType


class MIPStatus(Enum):
    IN_REVIEW = "In Review"
    REVIEW_PENDING = "Review Pending"
    COORDINATION = "Coordination"
    FINALIZATION = "Finalization"


@dataclass(frozen=True)
class MIPEntry(ComplexSerializableType):
    module_name: str
    vendor_name: str
    standard: str
    status: MIPStatus

    def to_dict(self):
        return {**self.__dict__, "status": self.status.value}

    @classmethod
    def from_dict(cls, dct: Mapping) -> "MIPEntry":
        return cls(
            dct["module_name"],
            dct["vendor_name"],
            dct["standard"],
            MIPStatus(dct["status"]),
        )


@dataclass
class MIPSnapshot(ComplexSerializableType):
    entries: Set[MIPEntry]
    timestamp: datetime
    last_updated: date

    def to_dict(self):
        return {
            "entries": list(self.entries),
            "timestamp": self.timestamp.isoformat(),
            "last_updated": self.last_updated.isoformat(),
        }

    @classmethod
    def from_dict(cls, dct: Mapping) -> "MIPSnapshot":
        return cls(
            set(dct["entries"]),
            datetime.fromisoformat(dct["timestamp"]),
            date.fromisoformat(dct["last_updated"]),
        )
