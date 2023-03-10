from __future__ import annotations

import datetime
import itertools
from dataclasses import dataclass
from typing import Any, ClassVar, Iterable

from dateutil.parser import isoparse

from sec_certs.sample.cpe import CPE, CPEConfiguration, cached_cpe
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.serialization.pandas import PandasSerializableType


@dataclass
class CVE(PandasSerializableType, ComplexSerializableType):
    @dataclass
    class Impact(ComplexSerializableType):
        base_score: float
        severity: str
        exploitability_score: float
        impact_score: float

        __slots__ = ["base_score", "severity", "exploitability_score", "impact_score"]

        @classmethod
        def from_nist_dict(cls, dct: dict[str, Any]) -> CVE.Impact:
            """
            Will load Impact from dictionary defined at https://nvd.nist.gov/feeds/json/cve/1.1
            """
            if not dct["impact"]:
                return cls(0, "", 0, 0)
            elif "baseMetricV3" in dct["impact"]:
                return cls(
                    dct["impact"]["baseMetricV3"]["cvssV3"]["baseScore"],
                    dct["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"],
                    dct["impact"]["baseMetricV3"]["exploitabilityScore"],
                    dct["impact"]["baseMetricV3"]["impactScore"],
                )
            elif "baseMetricV2" in dct["impact"]:
                return cls(
                    dct["impact"]["baseMetricV2"]["cvssV2"]["baseScore"],
                    dct["impact"]["baseMetricV2"]["severity"],
                    dct["impact"]["baseMetricV2"]["exploitabilityScore"],
                    dct["impact"]["baseMetricV2"]["impactScore"],
                )
            raise ValueError("NIST Dict for CVE Impact badly formatted.")

    cve_id: str
    vulnerable_cpes: list[CPE]
    vulnerable_cpe_configurations: list[CPEConfiguration]
    impact: Impact
    published_date: datetime.datetime | None
    cwe_ids: set[str] | None

    __slots__ = ["cve_id", "vulnerable_cpes", "vulnerable_cpe_configurations", "impact", "published_date", "cwe_ids"]

    pandas_columns: ClassVar[list[str]] = [
        "cve_id",
        "vulnerable_cpes",
        "base_score",
        "severity",
        "explotability_score",
        "impact_score",
        "published_date",
        "cwe_ids",
    ]

    # We cannot use frozen=True. It does not work with __slots__ prior to Python 3.10 dataclasses
    # Hence we manually provide __hash__ and __eq__ despite not guaranteeing immutability
    def __hash__(self) -> int:
        return hash(self.cve_id)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CVE) and self.cve_id == other.cve_id

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, CVE):
            raise ValueError(f"Cannot compare CVE with {type(other)} type.")
        self_year = int(self.cve_id.split("-")[1])
        self_id = int(self.cve_id.split("-")[2])
        other_year = int(other.cve_id.split("-")[1])
        other_id = int(other.cve_id.split("-")[2])

        return self_year < other_year if self_year != other_year else self_id < other_id

    @property
    def pandas_tuple(self):
        return (
            self.cve_id,
            self.vulnerable_cpes,
            self.impact.base_score,
            self.impact.severity,
            self.impact.exploitability_score,
            self.impact.impact_score,
            self.published_date,
            self.cwe_ids,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "vulnerable_cpes": self.vulnerable_cpes,
            "vulnerable_cpe_configurations": self.vulnerable_cpe_configurations,
            "impact": self.impact,
            "published_date": self.published_date.isoformat() if self.published_date else None,
            "cwe_ids": self.cwe_ids,
        }

    @classmethod
    def from_dict(cls, dct: dict[str, Any]) -> CVE:
        date_to_take = (
            isoparse(dct["published_date"]) if isinstance(dct["published_date"], str) else dct["published_date"]
        )
        return cls(
            dct["cve_id"],
            dct["vulnerable_cpes"],
            dct["vulnerable_cpe_configurations"],
            dct["impact"],
            date_to_take,
            dct["cwe_ids"],
        )

    @classmethod
    def from_nist_dict(cls, dct: dict) -> CVE:
        cve_id = dct["cve"]["CVE_data_meta"]["ID"]
        impact = cls.Impact.from_nist_dict(dct)
        published_date = isoparse(dct["publishedDate"])
        cwe_ids = cls.parse_cwe_data(dct)
        cpes, cpe_configurations = CVE.get_cpe_data_from_nodes_list(dct["configurations"]["nodes"])

        return cls(cve_id, cpes, cpe_configurations, impact, published_date, cwe_ids)

    @staticmethod
    def _parse_nist_cpe_dicts(dictionaries: Iterable[dict[str, Any]]) -> list[CPE]:
        cpes: list[CPE] = []

        for x in dictionaries:
            cpe_uri = x["cpe23Uri"]
            version_start: tuple[str, str] | None
            version_end: tuple[str, str] | None
            if "versionStartIncluding" in x and x["versionStartIncluding"]:
                version_start = ("including", x["versionStartIncluding"])
            elif "versionStartExcluding" in x and x["versionStartExcluding"]:
                version_start = ("excluding", x["versionStartExcluding"])
            else:
                version_start = None

            if "versionEndIncluding" in x and x["versionEndIncluding"]:
                version_end = ("including", x["versionEndIncluding"])
            elif "versionEndExcluding" in x and x["versionEndExcluding"]:
                version_end = ("excluding", x["versionEndExcluding"])
            else:
                version_end = None

            cpes.append(cached_cpe(cpe_uri, start_version=version_start, end_version=version_end))

        return cpes

    @staticmethod
    def _parse_nist_dict(cpe_list: list[dict[str, Any]], parse_only_vulnerable_cpes: bool) -> list[CPE]:
        """
        Method parses list of CPE dicts to the list of CPE objects.
        The <parse_only_vulnerable_cpes> parameter specifies if we want to
        parse only vulnerable CPEs or not.
        """
        return CVE._parse_nist_cpe_dicts(dct for dct in cpe_list if dct["vulnerable"] or not parse_only_vulnerable_cpes)

    @staticmethod
    def parse_cwe_data(dct: dict) -> set[str] | None:
        descriptions = dct["cve"]["problemtype"]["problemtype_data"][0]["description"]
        return {x["value"] for x in descriptions} if descriptions else None

    @staticmethod
    def get_cpe_data_from_nodes_list(lst: list) -> tuple[list[CPE], list[CPEConfiguration]]:
        or_nodes = [x for x in lst if x["operator"] == "OR"]
        and_nodes = [x for x in lst if x["operator"] == "AND"]
        return CVE.get_simple_cpes_from_nodes_list(or_nodes), CVE.get_cpe_configurations_from_node_list(and_nodes)

    @staticmethod
    def get_simple_cpes_from_nodes_list(lst: list) -> list[CPE]:
        return list(
            itertools.chain.from_iterable(
                CVE._parse_nist_dict(node["cpe_match"], parse_only_vulnerable_cpes=True) for node in lst
            )
        )

    @staticmethod
    def get_cpe_configurations_from_node_list(lst: list) -> list[CPEConfiguration]:
        """
        Retrieves only running on/with configurations, not the advanced ones.
        See more at https://nvd.nist.gov/vuln/vulnerability-detail-pages, section `Configurations`
        """
        configurations = [CVE.get_cpe_confiugration_from_node(x) for x in lst]
        return [x for x in configurations if x]

    @staticmethod
    def get_cpe_confiugration_from_node(node: dict) -> CPEConfiguration | None:
        if node["children"]:
            if len(node["children"]) != 2:
                return None

            # Deep variant should have two children, get CPEs from the first one and declare that product, second is platform
            cpes = CVE._parse_nist_dict(node["children"][0]["cpe_match"], parse_only_vulnerable_cpes=True)
            platform = CVE._parse_nist_dict(node["children"][1]["cpe_match"], parse_only_vulnerable_cpes=False)
            return CPEConfiguration(platform[0], cpes)
        else:
            # Shallow variant should have exactly 2 matching CPEs, we declare one a platform, second one the vuln. thing
            cpes = CVE._parse_nist_dict(node["cpe_match"], parse_only_vulnerable_cpes=True)

            if len(cpes) != 2:
                return None

            return CPEConfiguration(cpes[0], [cpes[1]])
