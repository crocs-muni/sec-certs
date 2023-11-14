from __future__ import annotations

import contextlib
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from sec_certs.configuration import config
from sec_certs.model.matching import AbstractMatcher
from sec_certs.sample.cc import CCCertificate
from sec_certs.sample.cc_certificate_id import CertificateId
from sec_certs.utils.strings import fully_sanitize_string


class CCSchemeMatcher(AbstractMatcher[CCCertificate]):
    """
    A heuristic matcher between entries on CC scheme websites (see CCSchemeDataset) and
    CC certificates from the Common Criteria portal (as in CCDataset).
    """

    def __init__(self, entry: Mapping, scheme: str):
        self.entry = entry
        self.scheme = scheme
        self._prepare()

    def _get_from_entry(self, *keys: str) -> str | None:
        for key in keys:
            if val := self.entry.get(key):
                return val
        if e := self.entry.get("enhanced"):
            for key in keys:
                if val := e.get(key):
                    return val
        return None

    def _prepare(self):
        self._canonical_cert_id = None
        if cert_id := self._get_from_entry("cert_id", "id"):
            with contextlib.suppress(Exception):
                self._canonical_cert_id = CertificateId(self.scheme, cert_id).canonical

        self._product = None
        if product_name := self._get_from_entry("product", "title", "name"):
            self._product = fully_sanitize_string(product_name)

        self._vendor = None
        if vendor_name := self._get_from_entry("vendor", "developer", "manufacturer", "supplier"):
            self._vendor = fully_sanitize_string(vendor_name)

        self._report_hash = self._get_from_entry("report_hash")
        self._target_hash = self._get_from_entry("target_hash")

    def match(self, cert: CCCertificate) -> float:
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
        cert_name = fully_sanitize_string(cert.name)
        cert_manufacturer = fully_sanitize_string(cert.manufacturer)
        # If we match exactly, return early.
        if self._product == cert.name and self._vendor == cert.manufacturer:
            return 99
        # If we match the report hash, return early.
        if cert.state.report_pdf_hash == self._report_hash and self._report_hash is not None:
            return 95
        # If we match the target hash, return early.
        if cert.state.st_pdf_hash == self._target_hash and self._target_hash is not None:
            return 93

        # Fuzzy match at the end with some penalization.
        product_rating = self._compute_match(self._product, cert_name)
        vendor_rating = self._compute_match(self._vendor, cert_manufacturer)
        return max((0, product_rating * 0.5 + vendor_rating * 0.5 - 2))

    @classmethod
    def match_all(
        cls, entries: list[dict[str, Any]], scheme: str, certificates: Iterable[CCCertificate]
    ) -> dict[str, dict[str, Any]]:
        """
        Match all entries of a given CC scheme to certificates from the dataset.

        :param entries: The entries from the scheme, obtained from CCSchemeDataset.
        :param scheme: The scheme, e.g. "DE".
        :param certificates: The certificates to match against.
        :return: A mapping of certificate digests to entries, without duplicates, not all entries may be present.
        """
        certs: list[CCCertificate] = list(filter(lambda cert: cert.scheme == scheme, certificates))
        matchers: Sequence[CCSchemeMatcher] = [CCSchemeMatcher(entry, scheme) for entry in entries]
        return cls._match_certs(matchers, certs, config.cc_matching_threshold)  # type: ignore
