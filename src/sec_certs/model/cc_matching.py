from __future__ import annotations

from typing import Mapping

from rapidfuzz import fuzz

from sec_certs.sample import CCCertificate, CertificateId
from sec_certs.utils.strings import fully_sanitize_string


class CCSchemeMatcher:
    """
    A heuristic matcher between entries on CC scheme websites (see CCSchemeDataset) and
    CC certificates from the Common Criteria portal (as in CCDataset).
    """

    def __init__(self, entry: Mapping, scheme: str):
        self.entry = entry
        self.scheme = scheme
        self._prepare()

    def _prepare(self):
        if cert_id := (self.entry.get("cert_id") or self.entry.get("id")):
            self._canonical_cert_id = CertificateId(self.scheme, cert_id).canonical
        else:
            self._canonical_cert_id = None
        self._product = fully_sanitize_string(self.entry.get("product") or self.entry.get("title"))
        self._vendor = fully_sanitize_string(
            self.entry.get("vendor")
            or self.entry.get("developer")
            or self.entry.get("manufacturer")
            or self.entry.get("supplier")
        )

    def match(self, cert: CCCertificate) -> float:
        """
        Compute the match of this matcher to the certificate, a float from 0 to 100.

        A 100 is a certificate ID match that should be always correct, assuming correct
        data in the entry and certificate.

        :param cert: The certificate to match against.
        :return: The match score.
        """
        if self.scheme != cert.scheme:
            return 0
        debuff = 0.0
        if self._canonical_cert_id:
            if cert.heuristics.cert_id == self._canonical_cert_id:
                return 100
            debuff = 0.5
        if self._product is None or self._vendor is None or cert.name is None or cert.manufacturer is None:
            return 0
        cert_name = fully_sanitize_string(cert.name)
        cert_manufacturer = fully_sanitize_string(cert.manufacturer)
        if self._product == cert.name and self._vendor == cert.manufacturer:
            return 99

        product_ratings = [
            fuzz.token_set_ratio(self._product, cert_name),
            fuzz.partial_token_sort_ratio(self._product, cert_name, score_cutoff=100),
        ]
        vendor_ratings = [
            fuzz.token_set_ratio(self._vendor, cert_manufacturer),
            fuzz.partial_token_sort_ratio(self._vendor, cert_manufacturer, score_cutoff=100),
        ]
        return max((0, max(product_ratings) * 0.5 + max(vendor_ratings) * 0.5 - 2)) * (1 - debuff)
