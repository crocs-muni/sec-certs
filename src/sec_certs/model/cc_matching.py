from __future__ import annotations

import contextlib
import re
from collections.abc import Iterable, Mapping, Sequence
from operator import itemgetter
from typing import Any

from sec_certs.cert_rules import rules
from sec_certs.configuration import config
from sec_certs.model.matching import AbstractMatcher
from sec_certs.sample.cc import CCCertificate
from sec_certs.sample.cc_certificate_id import CertificateId, schemes
from sec_certs.utils.sanitization import sanitize_link_fname
from sec_certs.utils.strings import fully_sanitize_string

CATEGORIES = {
    "ICs, Smart Cards and Smart Card-Related Devices and Systems",
    "Other Devices and Systems",
    "Network and Network-Related Devices and Systems",
    "Multi-Function Devices",
    "Boundary Protection Devices and Systems",
    "Data Protection",
    "Operating Systems",
    "Products for Digital Signatures",
    "Access Control Devices and Systems",
    "Mobility",
    "Databases",
    "Trusted Computing",
    "Detection Devices and Systems",
    "Key Management Systems",
    "Biometric Systems and Devices",
}


class CCSchemeMatcher(AbstractMatcher[CCCertificate]):
    """
    A heuristic matcher between entries on CC scheme websites (see CCSchemeDataset) and
    CC certificates from the Common Criteria portal (as in CCDataset).
    """

    def __init__(self, entry: Mapping, scheme: str):
        self.entry = entry
        self.scheme = scheme
        self._prepare()

    def _get_from_entry(self, *keys: str) -> Any | None:
        # Prefer enhanced over base
        if e := self.entry.get("enhanced"):
            for key in keys:
                if val := e.get(key):
                    return val
        for key in keys:
            if val := self.entry.get(key):
                return val
        return None

    def _prepare(self):  # noqa: C901
        self._canonical_cert_id = None
        self._cert_id = self._get_from_entry("cert_id", "id")
        if self._cert_id:
            with contextlib.suppress(Exception):
                self._canonical_cert_id = CertificateId(self.scheme, self._cert_id).canonical

        self._product = None
        if product_name := self._get_from_entry("product", "title", "name"):
            self._product = fully_sanitize_string(product_name)

        self._vendor = None
        if vendor_name := self._get_from_entry("vendor", "developer", "manufacturer", "supplier"):
            self._vendor = fully_sanitize_string(vendor_name)

        self._category = self._get_from_entry("category")
        self._certification_date = self._get_from_entry("certification_date")
        self._expiration_date = self._get_from_entry("expiration_date")
        self._level = self._get_from_entry("level", "assurance_level")
        if self._level:
            self._level = self._level.upper().replace("AUGMENTED", "").replace("WITH", "")

        filename_rules = rules["cc_filename_cert_id"][self.scheme]
        scheme_meta = schemes[self.scheme]
        if filename_rules and self._canonical_cert_id is None:
            cert_link = self._get_from_entry("cert_link")
            if cert_link:
                cert_fname = sanitize_link_fname(cert_link)
                for rule in filename_rules:
                    if match := re.match(rule, cert_fname):
                        with contextlib.suppress(Exception):
                            meta = match.groupdict()
                            self._canonical_cert_id = scheme_meta(meta)
                            break

            report_link = self._get_from_entry("report_link")
            if report_link and self._canonical_cert_id is None:
                report_fname = sanitize_link_fname(report_link)
                for rule in filename_rules:
                    if match := re.match(rule, report_fname):
                        with contextlib.suppress(Exception):
                            meta = match.groupdict()
                            self._canonical_cert_id = scheme_meta(meta)
                            break

        self._report_hash = self._get_from_entry("report_hash")
        self._target_hash = self._get_from_entry("target_hash")

    def match(self, cert: CCCertificate) -> float:  # noqa: C901
        """
        Compute the match of this matcher to the certificate, a float from 0 to 100.

        A 100 is a certificate ID match that should be always correct, assuming correct
        data in the entry and certificate.

        :param cert: The certificate to match against.
        :return: The match score.
        """
        # This one is full of magic numbers, there is some idea to it but adjust as necessary.
        # We want to match the same scheme.
        if self.scheme != cert.scheme:
            return 0
        # If we have a perfect cert_id match, take it.
        if self._canonical_cert_id and cert.heuristics.cert_id == self._canonical_cert_id:
            return 100
        # We need to have something to match to.
        if self._product is None or self._vendor is None or cert.name is None or cert.manufacturer is None:
            return 0
        # It is a correctly parsed category but the wrong one.
        if self._category in CATEGORIES and self._category != cert.category:
            return 0
        cert_name = fully_sanitize_string(cert.name)
        cert_manufacturer = fully_sanitize_string(cert.manufacturer)
        # If we match exactly, return early.
        if self._product == cert.name and self._vendor == cert.manufacturer:
            return 99
        # If we match the report hash, return early.
        if cert.state.report.pdf_hash == self._report_hash and self._report_hash is not None:
            return 95
        # If we match the target hash, return early.
        if cert.state.st.pdf_hash == self._target_hash and self._target_hash is not None:
            return 93

        # Fuzzy match at the end with some penalization.
        # Weigh the name and vendor more than the id and more than the level and certification date.
        # 6, 6, 4, 2, 2
        matches = {}
        product_rating = self._compute_match(self._product, cert_name)
        matches["product"] = (product_rating, 6)
        vendor_rating = self._compute_match(self._vendor, cert_manufacturer)
        matches["vendor"] = (vendor_rating, 6)

        if self._cert_id is not None and cert.heuristics.cert_id is not None:
            id_rating = self._compute_match(self._cert_id, cert.heuristics.cert_id)
            matches["id"] = (id_rating, 4)

        if self._certification_date is not None and cert.not_valid_before is not None:
            date_rating = 1
            if cert.not_valid_before.year == self._certification_date.year:
                date_rating += 33
            if cert.not_valid_before.month == self._certification_date.month:
                date_rating += 33
            if cert.not_valid_before.day == self._certification_date.day:
                date_rating += 33
            matches["certification_date"] = (date_rating, 2)

        if self._level is not None and cert.security_level:
            level_rating = self._compute_match(self._level, ", ".join(cert.security_level))
            matches["level"] = (level_rating, 2)
        total_weight = sum(map(itemgetter(1), matches.values()))
        return max((0, sum(match[0] * (match[1] / total_weight) for match in matches.values()) - 2))

    @classmethod
    def match_all(
        cls, entries: list[dict[str, Any]], scheme: str, certificates: Iterable[CCCertificate]
    ) -> tuple[dict[str, dict[str, Any]], dict[str, float]]:
        """
        Match all entries of a given CC scheme to certificates from the dataset.

        :param entries: The entries from the scheme, obtained from CCSchemeDataset.
        :param scheme: The scheme, e.g. "DE".
        :param certificates: The certificates to match against.
        :return: Two mappings:
                  - A mapping of certificate digests to entries, without duplicates, not all entries may be present.
                  - A mapping of certificate digests to scores that they matched with.
        """
        certs: list[CCCertificate] = list(filter(lambda cert: cert.scheme == scheme, certificates))
        matchers: Sequence[CCSchemeMatcher] = [CCSchemeMatcher(entry, scheme) for entry in entries]
        return cls._match_certs(matchers, certs, config.cc_matching_threshold)  # type: ignore
