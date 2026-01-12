from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from sec_certs.sample.certificate import Heuristics as BaseHeuristics
from sec_certs.sample.certificate import References
from sec_certs.sample.sar import SAR
from sec_certs.serialization.json import ComplexSerializableType


@dataclass
class Heuristics(BaseHeuristics, ComplexSerializableType):
    """
    Class for various heuristics related to CCCertificate
    """

    extracted_versions: set[str] | None = field(default=None)
    cpe_matches: set[str] | None = field(default=None)
    verified_cpe_matches: set[str] | None = field(default=None)
    related_cves: set[str] | None = field(default=None)
    cert_lab: list[str] | None = field(default=None)
    cert_id: str | None = field(default=None)
    prev_certificates: list[str] | None = field(default=None)
    next_certificates: list[str] | None = field(default=None)
    st_references: References = field(default_factory=References)
    report_references: References = field(default_factory=References)
    # Contains direct outward references merged from both st, and report sources, annotated with ReferenceAnnotator
    # TODO: Reference meanings as Enum if we work with it further.
    annotated_references: dict[str, str] | None = field(default=None)
    extracted_sars: set[SAR] | None = field(default=None)
    direct_transitive_cves: set[str] | None = field(default=None)
    indirect_transitive_cves: set[str] | None = field(default=None)
    scheme_data: dict[str, Any] | None = field(default=None)
    protection_profiles: set[str] | None = field(default=None)
    eal: str | None = field(default=None)

    @property
    def serialized_attributes(self) -> list[str]:
        return copy.deepcopy(super().serialized_attributes)
