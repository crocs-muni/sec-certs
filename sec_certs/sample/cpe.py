from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any, ClassVar

from sec_certs import constants
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.serialization.pandas import PandasSerializableType
from sec_certs.utils import helpers


@dataclass(init=False)
class CPE(PandasSerializableType, ComplexSerializableType):
    uri: str
    version: str
    vendor: str
    item_name: str
    title: str | None
    start_version: tuple[str, str] | None
    end_version: tuple[str, str] | None

    __slots__ = ["uri", "version", "vendor", "item_name", "title", "start_version", "end_version"]

    pandas_columns: ClassVar[list[str]] = [
        "uri",
        "vendor",
        "item_name",
        "version",
        "title",
    ]

    def __init__(
        self,
        uri: str,
        title: str | None = None,
        start_version: tuple[str, str] | None = None,
        end_version: tuple[str, str] | None = None,
    ):
        super().__init__()
        self.uri = uri

        splitted = helpers.split_unescape(self.uri, ":")
        self.vendor = " ".join(splitted[3].split("_"))
        self.item_name = " ".join(splitted[4].split("_"))
        self.version = self.normalize_version(" ".join(splitted[5].split("_")))
        self.title = title
        self.start_version = start_version
        self.end_version = end_version

    def __lt__(self, other: CPE) -> bool:
        return self.uri < other.uri

    @staticmethod
    def normalize_version(version: str) -> str:
        """
        Maps common empty versions (empty '', asterisk '*') to unified empty version (constants.CPE_VERSION_NA)
        """
        if version in {"", "*"}:
            return constants.CPE_VERSION_NA
        return version

    @classmethod
    def from_dict(cls, dct: dict[str, Any]) -> CPE:
        if isinstance(dct["start_version"], list):
            dct["start_version"] = tuple(dct["start_version"])
        if isinstance(dct["end_version"], list):
            dct["end_version"] = tuple(dct["end_version"])
        return super().from_dict(dct)

    @property
    def serialized_attributes(self) -> list[str]:
        return ["uri", "title", "start_version", "end_version"]

    @property
    def update(self) -> str:
        if self.uri is None:
            raise RuntimeError("URI is missing.")
        return " ".join(self.uri.split(":")[6].split("_"))

    @property
    def target_hw(self) -> str:
        if self.uri is None:
            raise RuntimeError("URI is missing.")
        return " ".join(self.uri.split(":")[10].split("_"))

    @property
    def pandas_tuple(self) -> tuple:
        return self.uri, self.vendor, self.item_name, self.version, self.title

    def __hash__(self) -> int:
        return hash((self.uri, self.start_version, self.end_version))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, self.__class__) and self.uri == other.uri


@lru_cache(maxsize=4096)
def cached_cpe(*args, **kwargs):
    return CPE(*args, **kwargs)
