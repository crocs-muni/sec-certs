from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from sec_certs.cert_rules import rules
from sec_certs.sample.cc_certificate_id import canonicalize, schemes
from sec_certs.sample.certificate import PdfData as BasePdfData
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils.extract import normalize_match_string


@dataclass
class PdfData(BasePdfData, ComplexSerializableType):
    """
    Class that holds data extracted from pdf files.
    """

    report_metadata: dict[str, Any] | None = field(default=None)
    st_metadata: dict[str, Any] | None = field(default=None)
    cert_metadata: dict[str, Any] | None = field(default=None)
    report_frontpage: dict[str, dict[str, Any]] | None = field(default=None)
    st_frontpage: dict[str, dict[str, Any]] | None = field(
        default=None
    )  # TODO: Unused, we have no frontpage matching for targets
    cert_frontpage: dict[str, dict[str, Any]] | None = field(
        default=None
    )  # TODO: Unused, we have no frontpage matching for certs
    report_keywords: dict[str, Any] | None = field(default=None)
    st_keywords: dict[str, Any] | None = field(default=None)
    cert_keywords: dict[str, Any] | None = field(default=None)
    report_filename: str | None = field(default=None)
    st_filename: str | None = field(default=None)
    cert_filename: str | None = field(default=None)

    def __bool__(self) -> bool:
        return any(x is not None for x in vars(self))

    @property
    def cert_lab(self) -> list[str] | None:
        """
        Returns labs for which certificate data was parsed.
        """
        if not self.report_frontpage:
            return None
        labs = [
            data["cert_lab"].split(" ")[0].upper()
            for scheme, data in self.report_frontpage.items()
            if data and "cert_lab" in data
        ]
        return labs if labs else None

    def frontpage_cert_id(self, scheme: str) -> dict[str, float]:
        """
        Get cert_id candidate from the frontpage of the report.
        """
        if not self.report_frontpage:
            return {}
        data = self.report_frontpage.get(scheme)
        if not data:
            return {}
        cert_id = data.get("cert_id")
        if not cert_id:
            return {}
        else:
            return {cert_id: 1.0}

    def filename_cert_id(self, scheme: str) -> dict[str, float]:
        """
        Get cert_id candidates from the matches in the report filename and cert filename.
        """
        scheme_filename_rules = rules["cc_filename_cert_id"][scheme]
        if not scheme_filename_rules:
            return {}
        scheme_meta = schemes[scheme]
        results: dict[str, float] = {}
        for fname in (self.report_filename, self.cert_filename):
            if not fname:
                continue

            matches: Counter = Counter()
            for rule in scheme_filename_rules:
                match = re.search(rule, fname)
                if match:
                    try:
                        meta = match.groupdict()
                        cert_id = scheme_meta(meta)
                        matches[cert_id] += 1
                    except Exception:
                        continue
            if not matches:
                continue
            total = max(matches.values())

            for candidate, count in matches.items():
                results.setdefault(candidate, 0)
                results[candidate] += count / total
        # TODO count length in weight
        return results

    def keywords_cert_id(self, scheme: str) -> dict[str, float]:
        """
        Get cert_id candidates from the keywords matches in the report and cert.
        """
        results: dict[str, float] = {}
        for keywords in (self.report_keywords, self.cert_keywords):
            if not keywords:
                continue
            cert_id_matches = keywords.get("cc_cert_id")
            if not cert_id_matches:
                continue

            if scheme not in cert_id_matches:
                continue
            matches: Counter = Counter(cert_id_matches[scheme])
            if not matches:
                continue
            total = max(matches.values())

            for candidate, count in matches.items():
                results.setdefault(candidate, 0)
                results[candidate] += count / total
        # TODO count length in weight
        return results

    def metadata_cert_id(self, scheme: str) -> dict[str, float]:
        """
        Get cert_id candidates from the report metadata.
        """
        scheme_rules = rules["cc_cert_id"][scheme]
        fields = ("/Title", "/Subject")
        results: dict[str, float] = {}
        for metadata in (self.report_metadata, self.cert_metadata):
            if not metadata:
                continue
            matches: Counter = Counter()
            for meta_field in fields:
                field_val = metadata.get(meta_field)
                if not field_val:
                    continue
                for rule in scheme_rules:
                    match = re.search(rule, field_val)
                    if match:
                        cert_id = normalize_match_string(match.group())
                        matches[cert_id] += 1
            if not matches:
                continue
            total = max(matches.values())

            for candidate, count in matches.items():
                results.setdefault(candidate, 0)
                results[candidate] += count / total
        # TODO count length in weight
        return results

    def candidate_cert_ids(self, scheme: str) -> dict[str, float]:
        frontpage_id = self.frontpage_cert_id(scheme)
        metadata_id = self.metadata_cert_id(scheme)
        filename_id = self.filename_cert_id(scheme)
        keywords_id = self.keywords_cert_id(scheme)

        # Join them and weigh them, each is normalized with weights from 0 to 1 (if anything is returned)
        candidates: dict[str, float] = defaultdict(lambda: 0.0)
        # TODO: Add heuristic based on ordering of ids (and extracted year + increment)
        # TODO: Add heuristic based on length
        # TODO: Add heuristic based on id "richness", we want to prefer IDs that have more components.
        # If we cannot canonicalize, just skip that ID.
        for candidate, count in frontpage_id.items():
            try:
                candidates[canonicalize(candidate, scheme)] += count * 1.5
            except Exception:
                continue
        for candidate, count in metadata_id.items():
            try:
                candidates[canonicalize(candidate, scheme)] += count * 1.2
            except Exception:
                continue
        for candidate, count in keywords_id.items():
            try:
                candidates[canonicalize(candidate, scheme)] += count * 1.0
            except Exception:
                continue
        for candidate, count in filename_id.items():
            try:
                candidates[canonicalize(candidate, scheme)] += count * 1.0
            except Exception:
                continue
        return candidates
