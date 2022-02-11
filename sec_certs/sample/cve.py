import datetime
import itertools
from dataclasses import dataclass
from typing import Any, ClassVar, Dict, List, Optional, Tuple

from dateutil.parser import isoparse

from sec_certs.sample.cpe import CPE, cached_cpe
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
    impact: Impact
    published_date: Optional[datetime.datetime]

    __slots__ = ["cve_id", "vulnerable_cpes", "impact", "published_date"]

    pandas_columns: ClassVar[List[str]] = [
        "cve_id",
        "vulnerable_cpes",
        "base_score",
        "severity",
        "explotability_score",
        "impact_score",
        "published_date",
    ]

    def __init__(self, cve_id: str, vulnerable_cpes: List[CPE], impact: Impact, published_date: str):
        super().__init__()
        self.cve_id = cve_id
        self.vulnerable_cpes = vulnerable_cpes
        self.impact = impact
        self.published_date = isoparse(published_date)

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
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "vulnerable_cpes": self.vulnerable_cpes,
            "impact": self.impact,
            "published_date": self.published_date.isoformat() if self.published_date else None,
        }

    @staticmethod
    def _parse_nist_dict(lst: List, cpe_uris: List) -> None:
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

                cpe_uris.append(cached_cpe(cpe_uri, start_version=version_start, end_version=version_end))

    @classmethod
    def from_nist_dict(cls, dct: Dict) -> "CVE":
        """
        Will load CVE from dictionary defined at https://nvd.nist.gov/feeds/json/cve/1.1
        """

        def get_vulnerable_cpes_from_nist_dict(dct: Dict) -> List[CPE]:
            def get_vulnerable_cpes_from_node(node: Dict) -> List[CPE]:
                cpe_uris = []
                if "children" in node:
                    for child in node["children"]:
                        cpe_uris += get_vulnerable_cpes_from_node(child)

                if "cpe_match" not in node:
                    return cpe_uris

                lst = node["cpe_match"]
                CVE._parse_nist_dict(lst, cpe_uris)

                return cpe_uris

            return list(
                itertools.chain.from_iterable(
                    [get_vulnerable_cpes_from_node(x) for x in dct["configurations"]["nodes"]]
                )
            )

        cve_id = dct["cve"]["CVE_data_meta"]["ID"]
        impact = cls.Impact.from_nist_dict(dct)
        vulnerable_cpes = get_vulnerable_cpes_from_nist_dict(dct)
        published_date = dct["publishedDate"]

        return cls(cve_id, vulnerable_cpes, impact, published_date)
