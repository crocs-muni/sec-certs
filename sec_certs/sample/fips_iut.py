from dataclasses import dataclass
from datetime import date, datetime
from typing import Mapping, Set

from sec_certs.serialization.json import ComplexSerializableType


@dataclass(frozen=True)
class IUTEntry(ComplexSerializableType):
    module_name: str
    vendor_name: str
    standard: str
    iut_date: date

    def to_dict(self):
        return {**self.__dict__, "iut_date": self.iut_date.isoformat()}

    @classmethod
    def from_dict(cls, dct: Mapping) -> "IUTEntry":
        return cls(
            dct["module_name"],
            dct["vendor_name"],
            dct["standard"],
            date.fromisoformat(dct["iut_date"]),
        )


@dataclass
class IUTSnapshot(ComplexSerializableType):
    entries: Set[IUTEntry]
    timestamp: datetime
    last_updated: date

    def to_dict(self):
        return {
            "entries": list(self.entries),
            "timestamp": self.timestamp.isoformat(),
            "last_updated": self.last_updated.isoformat(),
        }

    @classmethod
    def from_dict(cls, dct: Mapping) -> "IUTSnapshot":
        return cls(
            set(dct["entries"]),
            datetime.fromisoformat(dct["timestamp"]),
            date.fromisoformat(dct["last_updated"]),
        )