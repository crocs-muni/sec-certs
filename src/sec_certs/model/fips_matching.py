from __future__ import annotations

import typing
from collections.abc import Iterable, Mapping, Sequence
from datetime import date

from sec_certs.configuration import config
from sec_certs.model.matching import AbstractMatcher
from sec_certs.sample.fips import FIPSCertificate
from sec_certs.utils.strings import fully_sanitize_string

if typing.TYPE_CHECKING:
    from sec_certs.sample.fips_iut import IUTEntry, IUTSnapshot
    from sec_certs.sample.fips_mip import MIPEntry, MIPSnapshot


class FIPSProcessMatcher(AbstractMatcher[FIPSCertificate]):
    """
    A heuristic matcher between entries on the FIPS IUT/MIP lists and
    the FIPS certificates.
    """

    def __init__(self, entry: MIPEntry | IUTEntry, date: date | None = None):
        self.entry = entry
        self._prepare(date)

    def _prepare(self, date):
        self._date = date or getattr(self.entry, "status_since", None) or getattr(self.entry, "iut_date", None)
        self._product = fully_sanitize_string(self.entry.module_name)
        self._vendor = fully_sanitize_string(self.entry.vendor_name)
        self._standard = self.entry.standard

    def match(self, cert: FIPSCertificate) -> float:
        """
        Compute the match of this matcher to the certificate, a float from 0 to 100.

        :param cert: The certificate to match against.
        :return: The match score.
        """
        # We want to match the same standard.
        if cert.web_data.standard != self._standard:
            return 0
        # We need to have something to match to.
        if cert.name is None or cert.manufacturer is None:
            return 0
        # We can't match to a cert that predates us (MIP or IUT always predates the cert).
        if cert.web_data.validation_history and not any(
            validation_entry.date > self._date for validation_entry in cert.web_data.validation_history
        ):
            return 0
        # If we match exactly, return early.
        cert_name = fully_sanitize_string(cert.name)
        cert_manufacturer = fully_sanitize_string(cert.manufacturer)
        if self._product == cert_name and self._vendor == cert_manufacturer:
            return 99

        # Fuzzy match at the end with some penalization.
        product_rating = self._compute_match(self._product, cert_name)
        vendor_rating = self._compute_match(self._vendor, cert_manufacturer)
        return max((0, product_rating * 0.5 + vendor_rating * 0.5 - 2))

    @classmethod
    def match_snapshot(
        cls, snapshot: IUTSnapshot | MIPSnapshot, certificates: Iterable[FIPSCertificate]
    ) -> Mapping[IUTEntry | MIPEntry, FIPSCertificate | None]:
        """
        Match a whole snapshot of IUT/MIP entries to a FIPS certificate dataset.

        :param snapshot: The snapshot to match the entries of.
        :param certificates: The certificates to match against.
        :return: A mapping of certificate digests to entries, without duplicates, not all entries may be present.
        """
        certs: list[FIPSCertificate] = list(certificates)
        matchers: Sequence[FIPSProcessMatcher] = [
            FIPSProcessMatcher(entry, snapshot.timestamp.date()) for entry in snapshot
        ]
        # mypy is ridiculous
        return cls._match_certs(matchers, certs, config.fips_matching_threshold)  # type: ignore
