from __future__ import annotations

import typing
from typing import Iterable, Mapping, Sequence

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

    def __init__(self, entry: MIPEntry | IUTEntry):
        self.entry = entry
        self._prepare()

    def _prepare(self):
        self._product = fully_sanitize_string(self.entry.module_name)
        self._vendor = fully_sanitize_string(self.entry.vendor_name)
        self._standard = self.entry.standard

    def match(self, cert: FIPSCertificate) -> float:
        """
        Compute the match of this matcher to the certificate, a float from 0 to 100.

        :param cert: The certificate to match against.
        :return: The match score.
        """
        if cert.web_data.standard != self._standard:
            return 0
        if cert.name is None or cert.manufacturer is None:
            return 0
        cert_name = fully_sanitize_string(cert.name)
        cert_manufacturer = fully_sanitize_string(cert.manufacturer)
        if self._product == cert_name and self._vendor == cert_manufacturer:
            return 99

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
        matchers: Sequence[FIPSProcessMatcher] = [FIPSProcessMatcher(entry) for entry in snapshot]
        # mypy is ridiculous
        return cls._match_certs(matchers, certs, config.fips_matching_threshold)  # type: ignore
