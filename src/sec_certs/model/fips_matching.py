from __future__ import annotations

import typing
from operator import itemgetter
from typing import Mapping, MutableMapping

from rapidfuzz import fuzz

from sec_certs.configuration import config

if typing.TYPE_CHECKING:
    from sec_certs.dataset.fips import FIPSDataset
    from sec_certs.sample.fips import FIPSCertificate
    from sec_certs.sample.fips_iut import IUTEntry, IUTSnapshot
    from sec_certs.sample.fips_mip import MIPEntry, MIPSnapshot


class FIPSProcessMatcher:
    """
    A heuristic matcher between entries on the FIPS IUT/MIP lists and
    the FIPS certificates.
    """

    def __init__(self, entry: MIPEntry | IUTEntry):
        self.entry = entry
        self._prepare()

    def _prepare(self):
        self._product = self.entry.module_name
        self._vendor = self.entry.vendor_name
        self._standard = self.entry.standard
        self._date = getattr(self.entry, "status_since", None) or getattr(self.entry, "iut_date", None)

    def match(self, cert: FIPSCertificate) -> float:
        """
        Compute the match of this matcher to the certificate, a float from 0 to 100.

        :param cert: The certificate to match against.
        :return: The match score.
        """
        if cert.web_data.standard != self._standard:
            return 0
        if self._product is None or self._vendor is None:
            return 0
        if self._product == cert.name and self._vendor == cert.manufacturer:
            return 99
        # TODO: Move the CPE matching name/vendor normalization functions and use them here.

        product_ratings = [
            fuzz.token_set_ratio(self._product, cert.name),
            fuzz.partial_token_sort_ratio(self._product, cert.name, score_cutoff=100),
        ]
        vendor_ratings = [
            fuzz.token_set_ratio(self._vendor, cert.manufacturer),
            fuzz.partial_token_sort_ratio(self._vendor, cert.manufacturer, score_cutoff=100),
        ]
        return max((0, max(product_ratings) * 0.5 + max(vendor_ratings) * 0.5 - 2))

    @classmethod
    def match_snapshot(
        cls, snapshot: IUTSnapshot | MIPSnapshot, dset: FIPSDataset
    ) -> Mapping[IUTEntry | MIPEntry, FIPSCertificate | None]:
        """
        Match a whole snapshot of IUT/MIP entries to a FIPS certificate dataset.

        Duplicates may occur.

        :param snapshot: The snapshot to match the entries of.
        :param dset: The dataset tot match to.
        :return: The matching.
        """
        matches: MutableMapping[IUTEntry | MIPEntry, FIPSCertificate | None] = {}
        for entry in snapshot:
            matcher = FIPSProcessMatcher(entry)
            scores = sorted(((matcher.match(cert), cert) for cert in dset), key=itemgetter(0), reverse=True)
            found = False
            for score, cert in scores:
                if score < config.fips_matching_threshold:
                    break
                validations = cert.web_data.validation_history
                if not validations:
                    continue
                for validation in validations:
                    if validation.date >= snapshot.timestamp.date():
                        # It could be this cert, so take it
                        found = True
                        matches[entry] = cert
                        break
                if found:
                    break
                else:
                    matches[entry] = None
        return matches
