from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Any, ClassVar

from dateutil.parser import isoparse

from sec_certs.sample.cpe import CPEMatchCriteria, CPEMatchCriteriaConfiguration
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.serialization.pandas import PandasSerializableType


@dataclass
class CVE(PandasSerializableType, ComplexSerializableType):
    @dataclass
    class Metrics(ComplexSerializableType):
        base_score: float
        severity: str
        exploitability_score: float
        impact_score: float

        __slots__ = ["base_score", "severity", "exploitability_score", "impact_score"]

        @classmethod
        def from_nist_dict(cls, dct: dict[str, Any]) -> CVE.Metrics:
            """
            Loads metrics from dictionary
            """
            if not dct["metrics"]:
                return cls(0, "", 0, 0)
            metric_dct = CVE.Metrics.find_metrics_to_use(dct["metrics"])
            if not metric_dct:
                raise ValueError(f"Metrics dictionary for cve {dct['id']} present, but no suitable entry found.")
            return CVE.Metrics.from_metrics_dct(metric_dct)

        @staticmethod
        def find_metrics_to_use(dct: dict) -> dict | None:
            """
            any `Primary` entry available > any `nvd@nist.gov` entry available > just return the first entry if exists.
            """
            all_metrics = dct.get("cvssMetricV31", []) + dct.get("cvssMetricV30", []) + dct.get("cvssMetricV2", [])

            for element in all_metrics:
                if element["type"] == "Primary":
                    return element
            for element in all_metrics:
                if element["source"] == "nvd@nist.gov":
                    return element

            if all_metrics:
                return all_metrics[0]

            return None

        @classmethod
        def from_metrics_dct(cls, dct: dict) -> CVE.Metrics:
            if dct["cvssData"]["version"] == "3.1":
                return cls(
                    dct["cvssData"]["baseScore"],
                    dct["cvssData"]["baseSeverity"],
                    dct["exploitabilityScore"],
                    dct["impactScore"],
                )
            if dct["cvssData"]["version"] == "3.0":
                return cls(
                    dct["cvssData"]["baseScore"],
                    dct["cvssData"]["baseSeverity"],
                    dct["exploitabilityScore"],
                    dct["impactScore"],
                )
            if dct["cvssData"]["version"] == "2.0":
                return cls(
                    dct["cvssData"]["baseScore"],
                    dct["baseSeverity"],
                    dct["exploitabilityScore"],
                    dct["impactScore"],
                )
            raise ValueError(f"Unknown CVSS version occured ({dct['cvssData']['version']}) when parsing CVSS metrics.")

    cve_id: str
    vulnerable_criteria: list[CPEMatchCriteria]
    vulnerable_criteria_configurations: list[CPEMatchCriteriaConfiguration]
    metrics: Metrics
    published_date: datetime.datetime | None
    cwe_ids: set[str] | None

    __slots__ = [
        "cve_id",
        "vulnerable_criteria",
        "vulnerable_criteria_configurations",
        "metrics",
        "published_date",
        "cwe_ids",
    ]

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
            self.vulnerable_criteria,
            self.metrics.base_score,
            self.metrics.severity,
            self.metrics.exploitability_score,
            self.metrics.impact_score,
            self.published_date,
            self.cwe_ids,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "vulnerable_cpes": self.vulnerable_criteria,
            "vulnerable_criteria_configurations": self.vulnerable_criteria_configurations,
            "impact": self.metrics,
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
            dct["vulnerable_criteria_configurations"],
            dct["impact"],
            date_to_take,
            dct["cwe_ids"],
        )

    @classmethod
    def from_nist_dict(cls, dct: dict) -> CVE:
        cve_id = dct["id"]
        metrics = cls.Metrics.from_nist_dict(dct)
        published_date = datetime.datetime.fromisoformat(dct["published"])
        cwe_ids = cls.parse_cwe_data(dct)
        vulnerable_criteria, vulnerable_criteria_configurations = CVE.parse_configurations(dct)
        return cls(cve_id, vulnerable_criteria, vulnerable_criteria_configurations, metrics, published_date, cwe_ids)

    @staticmethod
    def parse_cwe_data(dct: dict) -> set[str] | None:
        if "weaknesses" not in dct:
            return None

        descriptions = [x["description"] for x in dct["weaknesses"]]
        cwes = {x["value"] for description in descriptions for x in description}
        return cwes if cwes else None

    @staticmethod
    def parse_configurations(
        dct: dict[str, Any],
    ) -> tuple[list[CPEMatchCriteria], list[CPEMatchCriteriaConfiguration]]:
        criteria = []
        criteria_configurations = []
        configurations = dct.get("configurations", [])

        for conf in configurations:
            new_criteria, new_criteria_configuration = CVE.parse_single_configuration(conf)
            criteria.extend(new_criteria)
            if new_criteria_configuration:
                criteria_configurations.append(new_criteria_configuration)
        return criteria, criteria_configurations

    @staticmethod
    def parse_single_configuration(
        configuration: dict[str, Any]
    ) -> tuple[list[CPEMatchCriteria], CPEMatchCriteriaConfiguration | None]:
        if CVE.configuration_is_simple(configuration):
            return CVE.get_simple_criteria_from_cpe_matches(configuration["nodes"][0]["cpeMatch"]), None
        else:
            return [], CVE.get_configuration_criteria_from_configuration_nodes(configuration["nodes"])

    @staticmethod
    def configuration_is_simple(configuration: dict) -> bool:
        return (
            len(configuration["nodes"]) == 1
            and "cpeMatch" in configuration["nodes"][0]
            and (configuration.get("operator", "OR") == "OR" or len(configuration["nodes"][0]["cpeMatch"]) == 1)
        )

    @staticmethod
    def get_configuration_criteria_from_configuration_nodes(
        configuration_nodes: dict,
    ) -> CPEMatchCriteriaConfiguration | None:
        """
        Retrieves complex configuration criteria from a dictionary of configuration nodes.
        It is aasserted that the dictionary has two layers at most, that the top-level children are in AND relationship,
        and that the individual elements are in OR relationship (otherwise, they would be parsed by different method.)

        We cannot process configuration when elements of a single component are in AND relationship.
        Out of all configurations in dataset as of April 2023, only 3 were detected in the dataset.
        We ignore those on purpose.

        :param dict configuration_nodes: _description_
        :return CPEMatchCriteriaConfiguration | None: _description_
        """
        assert all("cpeMatch" in x for x in configuration_nodes)  # the next layer are matches
        nodes = [x for x in configuration_nodes if "operator" not in x or x["operator"] == "OR"]
        if nodes:
            return CPEMatchCriteriaConfiguration(
                [CVE.get_simple_criteria_from_cpe_matches(x["cpeMatch"]) for x in nodes]
            )
        return None

    @staticmethod
    def get_simple_criteria_from_cpe_matches(cpe_matches: list[dict[str, Any]]) -> list[CPEMatchCriteria]:
        return [CPEMatchCriteria.from_nist_dict(x) for x in cpe_matches]
