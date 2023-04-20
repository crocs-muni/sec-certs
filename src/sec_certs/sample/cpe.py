from __future__ import annotations

from dataclasses import dataclass, field
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
    This class represents a list of lists of `CPEMatchCriteria` objects, where there's an OR relation between the
    elements of the inner list and AND relation between the elements of the outer list.
    Our experiments confirm that there are only 3 distinct CVEs in the database that allow AND configuration between
    the elements. Simplyfing to ORs enables much more simple implementation.
    """

    components: list[list[CPEMatchCriteria]]
    _expanded_components: list[list[str]] = field(default_factory=list)

    def matches(self, cpe_uris: set[str]) -> bool:
        """
        Returns if given set of cpe_ids matches this configuration.
        """
        if not self._expanded_components:
            raise ValueError(
                "Cannot match to CPEMatchConfiguration when attribute _expanded_components was not filled-in. That attribute is prepared by `CVEDataset.build_lookup_dict()`."
            )
        return all(any(x in component for x in cpe_uris) for component in self._expanded_components)

    @property
    def serialized_attributes(self) -> list[str]:
        return ["components"]

    def expand_and_filter(self, match_dict: dict, relevant_cpe_uris: set[str] | None):
        """
        Expands the components to actual CPE records that are held in `_expanded_components` attribute.
        Additionally, this filters the elements of the expanded components only to `relevant_cpe_uris`, which speeds-up
        the computation.
        """
        self._expanded_components = []
        for component in self.components:
            expanded_component: list[str] = []
            for criteria in component:
                if criteria.criteria_id not in match_dict["match_strings"]:
                    continue
                expanded_component.extend(
                    x["cpeName"] for x in match_dict["match_strings"][criteria.criteria_id]["matches"]
                )
            if relevant_cpe_uris:
                expanded_component = [x for x in expanded_component if x in relevant_cpe_uris]
            self._expanded_components.append(expanded_component)


@dataclass
class CPE(PandasSerializableType, ComplexSerializableType):
    cpe_id: str
    uri: str
    version: str
    vendor: str
    item_name: str
    title: str | None

    __slots__ = ["cpe_id", "uri", "version", "vendor", "item_name", "title"]

    pandas_columns: ClassVar[list[str]] = [
        "uri",
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
    ):
        super().__init__()
        self.cpe_id = cpe_id
        self.uri = uri

        splitted = helpers.split_unescape(self.uri, ":")
        self.vendor = " ".join(splitted[3].split("_"))
        self.item_name = " ".join(splitted[4].split("_"))
        self.version = self.normalize_version(" ".join(splitted[5].split("_")))
        self.title = title

    # We cannot use frozen=True. It does not work with __slots__ prior to Python 3.10 dataclasses
    # Hence we manually provide __hash__ and __eq__ despite not guaranteeing immutability
    def __hash__(self) -> int:
        return hash(self.uri)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, self.__class__) and self.uri == other.uri

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
    def from_nvd_dict(cls, dct: dict[str, Any]) -> CPE:
        title = [x for x in dct["titles"] if x["lang"] == "en"][0]["title"]
        return cls(dct["cpeNameId"], dct["cpeName"], title)

    @property
    def serialized_attributes(self) -> list[str]:
        return ["cpe_id", "uri", "title"]

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
