from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any, ClassVar

from sec_certs import constants
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.serialization.pandas import PandasSerializableType
from sec_certs.utils import helpers


@dataclass
class CPEMatchCriteria(ComplexSerializableType):
    vulnerable: bool
    criteria: str
    criteria_id: str
    version_start: tuple[str, str] | None
    version_end: tuple[str, str] | None

    __slots__ = ["vulnerable", "criteria", "criteria_id", "version_start", "version_end"]

    # We cannot use frozen=True. It does not work with __slots__ prior to Python 3.10 dataclasses
    # Hence we manually provide __hash__ and __eq__ despite not guaranteeing immutability
    def __hash__(self) -> int:
        return hash(self.criteria_id)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CPEMatchCriteria) and self.criteria_id == other.criteria_id

    def __lt__(self, other: CPEMatchCriteria) -> bool:
        return self.criteria_id < other.criteria_id

    @classmethod
    def from_nist_dict(cls, dct: dict[str, Any]) -> CPEMatchCriteria:
        if dct.get("versionStartIncluding", None):
            version_start = ("including", dct["versionStartIncluding"])
        elif dct.get("versionStartExcluding"):
            version_start = ("excluding", dct["versionStartExcluding"])
        else:
            version_start = None

        if dct.get("versionEndIncluding", None):
            version_end = ("including", dct["versionEndIncluding"])
        elif dct.get("versionEndExcluding", None):
            version_end = ("excluding", dct["versionEndExcluding"])
        else:
            version_end = None

        return cls(dct["vulnerable"], dct["criteria"], dct["matchCriteriaId"], version_start, version_end)


@dataclass
class CPEMatchCriteriaConfiguration(ComplexSerializableType):
    """
    This class represents a set of sets of `CPEMatchCriteria` objects, where there's an OR relation between the
    elements of the set.
    Our experiments confirm that there are only 3 distinct CVEs in the database that allow AND configuration between
    the elements. Simplyfing to ORs enables much more simple implementation.
    """

    components: list[list[CPEMatchCriteria]]
    __slots__ = ["components"]


@dataclass
class CPEConfiguration(ComplexSerializableType):
    __slots__ = ["platform", "cpes"]

    platform: CPE
    cpes: list[CPE]

    def __hash__(self) -> int:
        return hash(self.platform) + sum([hash(cpe) for cpe in self.cpes])

    def __lt__(self, other: CPEConfiguration) -> bool:
        return self.platform < other.platform

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, self.__class__) and self.platform == other.platform and set(self.cpes) == set(other.cpes)
        )

    def matches(self, other_cpe_uris: set[str]) -> bool:
        """
        For a given set of CPEs method returns boolean if the CPE configuration is
        matched or not.
        """
        return self.platform.uri in other_cpe_uris and any(x.uri in other_cpe_uris for x in self.cpes)

    def get_all_cpes(self) -> set[CPE]:
        return {self.platform}.union(self.cpes)


@dataclass
class CPE(PandasSerializableType, ComplexSerializableType):
    cpe_id: str
    uri: str
    version: str
    vendor: str
    item_name: str
    title: str | None
    start_version: tuple[str, str] | None
    end_version: tuple[str, str] | None

    __slots__ = ["cpe_id", "uri", "version", "vendor", "item_name", "title", "start_version", "end_version"]

    pandas_columns: ClassVar[list[str]] = [
        "cpe_id" "uri",
        "vendor",
        "item_name",
        "version",
        "title",
    ]

    def __init__(
        self,
        cpe_id: str,
        uri: str,
        title: str | None = None,
        start_version: tuple[str, str] | None = None,
        end_version: tuple[str, str] | None = None,
    ):
        super().__init__()
        self.cpe_id = cpe_id
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

    @classmethod
    def from_nvd_dict(cls, dct: dict[str, Any]) -> CPE:
        title = [x for x in dct["titles"] if x["lang"] == "en"][0]["title"]
        return cls(dct["cpeNameId"], dct["cpeName"], title, None, None)

    @property
    def serialized_attributes(self) -> list[str]:
        return ["cpe_id", "uri", "title", "start_version", "end_version"]

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

    # We cannot use frozen=True. It does not work with __slots__ prior to Python 3.10 dataclasses
    # Hence we manually provide __hash__ and __eq__ despite not guaranteeing immutability
    def __hash__(self) -> int:
        return hash((self.uri, self.start_version, self.end_version))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, self.__class__) and self.uri == other.uri


@lru_cache(maxsize=4096)
def cached_cpe(*args, **kwargs):
    return CPE(*args, **kwargs)
