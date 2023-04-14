from __future__ import annotations

import typing
from heapq import heappop, heappush
from typing import Any, Mapping

from rapidfuzz import fuzz

from sec_certs.configuration import config

if typing.TYPE_CHECKING:
    from sec_certs.dataset.cc import CCDataset
    from sec_certs.sample.cc import CCCertificate

from sec_certs.sample.cc_certificate_id import CertificateId
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
        if cert_id := self._get_from_entry("cert_id", "id"):
            self._canonical_cert_id = CertificateId(self.scheme, cert_id).canonical
        else:
            self._canonical_cert_id = None

        if product_name := self._get_from_entry("product", "title", "name"):
            self._product = fully_sanitize_string(product_name)
        else:
            self._product = None

        if vendor_name := self._get_from_entry("vendor", "developer", "manufacturer", "supplier"):
            self._vendor = fully_sanitize_string(vendor_name)
        else:
            self._vendor = None

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
        if self._canonical_cert_id and cert.heuristics.cert_id == self._canonical_cert_id:
            return 100
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
        return max((0, max(product_ratings) * 0.5 + max(vendor_ratings) * 0.5 - 2))

    @classmethod
    def match_all(cls, entries: list[dict[str, Any]], scheme: str, dset: CCDataset):
        certs: list[CCCertificate] = list(filter(lambda cert: cert.scheme == scheme, dset))
        matchers = [CCSchemeMatcher(entry, scheme) for entry in entries]
        scores: list[tuple[float, int, int]] = []
        matched_is: set[int] = set()
        matched_js: set[int] = set()
        for i, cert in enumerate(certs):
            for j, matcher in enumerate(matchers):
                score = matcher.match(cert)
                triple = (100 - score, i, j)
                heappush(scores, triple)
        results = {}
        for triple in (heappop(scores) for _ in range(len(scores))):
            inv_score, i, j = triple
            # Do not match already matched entries/certs.
            if i in matched_is or j in matched_js:
                continue
            # Compute the actual score from the inverse.
            score = 100 - inv_score
            # Do not match if we are below threshold, all the following will be as well.
            if score < config.cc_matching_threshold:
                break
            # Match cert dgst to entry
            cert = certs[i]
            entry = matchers[j].entry
            results[cert.dgst] = entry
        return results
