from __future__ import annotations

import datetime
import itertools
from dataclasses import dataclass
from typing import Any, ClassVar, Dict, List, Optional, Set, Tuple

from dateutil.parser import isoparse

from sec_certs.sample.cpe import CPE, CPEConfiguration, cached_cpe
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.serialization.pandas import PandasSerializableType


@dataclass(init=False)
class CVE(PandasSerializableType, ComplexSerializableType):
    @dataclass(eq=True)
    class Impact(ComplexSerializableType):
        base_score: float
        severity: str
        exploitability_score: float
        impact_score: float

        __slots__ = ["base_score", "severity", "exploitability_score", "impact_score"]

        @classmethod
        def from_nist_dict(cls, dct: Dict[str, Any]) -> "CVE.Impact":
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
    vulnerable_cpes: List[CPE]
    vulnerable_cpe_configurations: list[CPEConfiguration]
    impact: Impact
    published_date: Optional[datetime.datetime]
    cwe_ids: Optional[Set[str]]

    __slots__ = ["cve_id", "vulnerable_cpes", "impact", "published_date", "cwe_ids"]

    pandas_columns: ClassVar[List[str]] = [
        "cve_id",
        "vulnerable_cpes",
        "base_score",
        "severity",
        "explotability_score",
        "impact_score",
        "published_date",
        "cwe_ids",
    ]

    def __init__(
        self,
        cve_id: str,
        vulnerable_cpes: List[CPE],
        vulnerable_cpe_configurations: list[CPEConfiguration],
        impact: Impact,
        published_date: str,
        cwe_ids: Optional[Set[str]],
    ):
        super().__init__()
        self.cve_id = cve_id
        self.vulnerable_cpes = vulnerable_cpes
        self.vulnerable_cpe_configurations = vulnerable_cpe_configurations
        self.impact = impact
        self.published_date = isoparse(published_date)
        self.cwe_ids = cwe_ids

    def __hash__(self) -> int:
        return hash(self.cve_id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CVE):
            return False
        return self.cve_id == other.cve_id

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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "vulnerable_cpes": self.vulnerable_cpes,
            "impact": self.impact,
            "published_date": self.published_date.isoformat() if self.published_date else None,
            "cwe_ids": self.cwe_ids,
        }

    @staticmethod
    def _parse_nist_dict(lst: List) -> List[CPE]:
        cpes: List[CPE] = []

        for x in lst:
            if x["vulnerable"]:
                cpe_uri = x["cpe23Uri"]
                version_start: Optional[Tuple[str, str]]
                version_end: Optional[Tuple[str, str]]
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
    def _parse_cpe_list(lst: List) -> list[CPE]:
        cpes: List[CPE] = []

        for x in lst:
            cpe_uri = x["cpe23Uri"]
            version_start: Optional[Tuple[str, str]]
            version_end: Optional[Tuple[str, str]]
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

    @classmethod
    def from_nist_dict(cls, dct: Dict) -> CVE:
        """
        Will load CVE from dictionary defined at https://nvd.nist.gov/feeds/json/cve/1.1
        """

        def get_cpe_configurations_from_and_cpe_dict(children: list[dict]) -> list[CPEConfiguration]:
            configurations: list[CPEConfiguration] = []

            if not children or len(children) != 2:
                return configurations

            cpes = CVE._parse_cpe_list(children[0]["cpe_match"])
            cpe_uris = [cpe.uri for cpe in cpes]
            platforms = CVE._parse_cpe_list(children[1]["cpe_match"])

            return [CPEConfiguration(platform.uri, cpe_uris) for platform in platforms]

        def get_vulnerable_cpes_from_nist_dict(dct: Dict) -> tuple[list[CPE], list[CPEConfiguration]]:
            def get_vulnerable_cpes_and_cpe_configurations(
                node: Dict, cpes: list[CPE], cpe_configurations: list[CPEConfiguration]
            ) -> tuple[list[CPE], list[CPEConfiguration]]:
                if node["operator"] == "AND":
                    cpe_configurations.extend(get_cpe_configurations_from_and_cpe_dict(node["children"]))

                if "children" in node:
                    for child in node["children"]:
                        get_vulnerable_cpes_and_cpe_configurations(child, cpes, cpe_configurations)

                if "cpe_match" not in node:
                    return cpes, cpe_configurations

                candidates = node["cpe_match"]
                cpes.extend(CVE._parse_nist_dict(candidates))

                return cpes, cpe_configurations

            cpes_and_cpe_configurations = [
                get_vulnerable_cpes_and_cpe_configurations(x, [], []) for x in dct["configurations"]["nodes"]
            ]
            vulnerable_cpes = list(itertools.chain.from_iterable(map(lambda x: x[0], cpes_and_cpe_configurations)))
            vulnerable_cpe_configurations = list(
                itertools.chain.from_iterable(map(lambda x: x[1], cpes_and_cpe_configurations))
            )

            return vulnerable_cpes, vulnerable_cpe_configurations

        cve_id = dct["cve"]["CVE_data_meta"]["ID"]
        impact = cls.Impact.from_nist_dict(dct)
        vulnerable_cpes, vulnerable_cpe_configurations = get_vulnerable_cpes_from_nist_dict(dct)
        published_date = dct["publishedDate"]
        cwe_ids = cls.parse_cwe_data(dct)

        return cls(cve_id, vulnerable_cpes, vulnerable_cpe_configurations, impact, published_date, cwe_ids)

    @staticmethod
    def parse_cwe_data(dct: Dict) -> Optional[Set[str]]:
        descriptions = dct["cve"]["problemtype"]["problemtype_data"][0]["description"]
        return {x["value"] for x in descriptions} if descriptions else None
