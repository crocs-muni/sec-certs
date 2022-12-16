from __future__ import annotations

import datetime
import itertools
from dataclasses import dataclass
from typing import Any, ClassVar

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

    def __init__(
        self,
        cve_id: str,
        vulnerable_cpes: list[CPE],
        vulnerable_cpe_configurations: list[CPEConfiguration],
        impact: Impact,
        published_date: str,
        cwe_ids: set[str] | None,
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "vulnerable_cpes": self.vulnerable_cpes,
            "vulnerable_cpe_configurations": self.vulnerable_cpe_configurations,
            "impact": self.impact,
            "published_date": self.published_date.isoformat() if self.published_date else None,
            "cwe_ids": self.cwe_ids,
        }

    @staticmethod
    def _parse_nist_cpe_dicts(lst: list[dict[str, Any]]) -> list[CPE]:
        cpes: list[CPE] = []

        for x in lst:
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
        cpe_dicts_to_be_parsed = cpe_list

        if parse_only_vulnerable_cpes:
            cpe_dicts_to_be_parsed = [dct for dct in cpe_list if dct["vulnerable"]]

        return CVE._parse_nist_cpe_dicts(cpe_dicts_to_be_parsed)

    @classmethod
    def from_nist_dict(cls, dct: dict) -> CVE:
        """
        Will load CVE from dictionary defined at https://nvd.nist.gov/feeds/json/cve/1.1
        """

        def get_cpe_configurations_from_and_cpe_dict(children: list[dict]) -> list[CPEConfiguration]:
            configurations: list[CPEConfiguration] = []

            if not children or len(children) != 2:
                return configurations

            cpes = CVE._parse_nist_dict(children[0]["cpe_match"], True)
            vulnerable_cpe_uris = {cpe.uri for cpe in cpes}

            if not cpes:
                return configurations

            # Platform does not have to be vulnerable necessarily
            platforms = CVE._parse_nist_dict(children[1]["cpe_match"], False)

            return [CPEConfiguration(platform.uri, vulnerable_cpe_uris) for platform in platforms]

        def get_vulnerable_cpes_from_nist_dict(dct: dict) -> tuple[list[CPE], list[CPEConfiguration]]:
            def get_vulnerable_cpes_and_cpe_configurations(
                node: dict, cpes: list[CPE], cpe_configurations: list[CPEConfiguration]
            ) -> tuple[list[CPE], list[CPEConfiguration]]:
                """
                Method traverses node of CPE tree and returns the list of CPEs and CPE configuratios,
                which depends on if the parent node is OR/AND type.
                """
                if node["operator"] == "AND":
                    cpe_configurations.extend(get_cpe_configurations_from_and_cpe_dict(node["children"]))
                    return cpes, cpe_configurations

                if "children" in node:
                    for child in node["children"]:
                        get_vulnerable_cpes_and_cpe_configurations(child, cpes, cpe_configurations)

                if "cpe_match" not in node:
                    return cpes, cpe_configurations

                candidates = node["cpe_match"]
                cpes.extend(CVE._parse_nist_dict(candidates, True))

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
    def parse_cwe_data(dct: dict) -> set[str] | None:
        descriptions = dct["cve"]["problemtype"]["problemtype_data"][0]["description"]
        return {x["value"] for x in descriptions} if descriptions else None
