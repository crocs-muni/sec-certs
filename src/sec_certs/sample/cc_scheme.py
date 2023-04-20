from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from sec_certs.serialization.json import ComplexSerializableType


class EntryType(Enum):
    Certified = "CERTIFIED"
    InEvaluation = "INEVALUATION"
    Archived = "ARCHIVED"


@dataclass
class CCScheme(ComplexSerializableType):
    """
    Dataclass for data extracted from a CCScheme website, so more like a
    "CCSchemeWebDump" but that classname is not so nice.

    Contains the country (scheme) code a timestamp of extraction and
    several lists of entries: certified, in-evaluation and archived.
    It may only contain some lists of entries as the scheme might only publish
    them.
    """

    country: str
    timestamp: datetime
    lists: dict[EntryType, Any]

    @classmethod
    def from_dict(cls, dct):
        return cls(
            dct["country"],
            datetime.fromisoformat(dct["timestamp"]),
            {EntryType(entry_type): entries for entry_type, entries in dct["lists"].items()},
        )

    def to_dict(self):
        return {
            "country": self.country,
            "timestamp": self.timestamp.isoformat(),
            "lists": {entry_type.value: entries for entry_type, entries in self.lists.items()},
        }
