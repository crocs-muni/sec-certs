from __future__ import annotations

from rapidfuzz import fuzz

from sec_certs.sample import FIPSCertificate, IUTEntry, MIPEntry


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
        # TODO: Add logic to match on date?
        #       Certification date should be after the entry date in MIP/IUT.
        #       But a FIPS cert can have many validation dates, gets tricky.
        #       Maybe this needs to be done outside of the matcher context,
        #       when comparing several matches.
        if cert.web_data.standard != self._standard:
            return 0
        if self._product is None or self._vendor is None:
            return 0
        if self._product == cert.name and self._vendor == cert.manufacturer:
            return 99

        product_ratings = [
            fuzz.token_set_ratio(self._product, cert.name),
            fuzz.partial_token_sort_ratio(self._product, cert.name, score_cutoff=100),
        ]
        vendor_ratings = [
            fuzz.token_set_ratio(self._vendor, cert.manufacturer),
            fuzz.partial_token_sort_ratio(self._vendor, cert.manufacturer, score_cutoff=100),
        ]
        return max((0, max(product_ratings) * 0.5 + max(vendor_ratings) * 0.5 - 2))
