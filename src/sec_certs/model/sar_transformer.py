from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import cast

from sec_certs.sample.cc import CCCertificate
from sec_certs.sample.sar import SAR, SAR_DICT_KEY

logger = logging.getLogger(__name__)


# TODO: Right now we ignore number of ocurrences for final SAR selection. If we keep it this way, we can discard that variable
class SARTransformer:
    """
    Class for transforming SARs defined in st_keywords and report_keywords dictionaries into SAR objects.
    This class implements `sklearn.base.Transformer` interface, so fit_transform() can be called on it.
    """

    def fit(self, certificates: Iterable[CCCertificate]) -> SARTransformer:
        """
        Just returns self, no fitting needed

        :param Iterable[CCCertificate] certificates: Unused parameter
        :return SARTransformer: return self
        """
        return self

    def fit_transform(self, X, y=None, **fit_params):
        return self.fit(X).transform(X)

    def transform(self, certificates: Iterable[CCCertificate]) -> list[set[SAR] | None]:
        """
        Just a wrapper around transform_single_cert() called on an iterable of CCCertificate.

        :param Iterable[CCCertificate] certificates: Iterable of CCCertificate objects to perform the extraction on.
        :return List[Optional[Set[SAR]]]: Returns List of results from transform_single_cert().
        """
        return [self.transform_single_cert(cert) for cert in certificates]

    def transform_single_cert(self, cert: CCCertificate) -> set[SAR] | None:
        """
        Given CCCertificate, will transform SAR keywords extracted from txt files
        into a set of SAR objects. Also handles extractin of correct SAR levels, duplicities and filtering.
        Uses three sources: CSV scan, security target, and certification report.
        The caller should assure that the certificates have the keywords extracted.

        :param CCCertificate cert: Certificate to extract SARs from
        :return Optional[Set[SAR]]: Set of SARs, None if none were identified.
        """
        sec_level_candidates, st_candidates, report_candidates = self._collect_sar_candidates_from_all_sources(cert)
        return self._resolve_candidate_conflicts(sec_level_candidates, st_candidates, report_candidates, cert.dgst)

    @staticmethod
    def _collect_sar_candidates_from_all_sources(cert: CCCertificate) -> tuple[set[SAR], set[SAR], set[SAR]]:
        """
        Parses SARs from three distinct sources and returns the results as a three tuple:
        - Security level from CSV scan
        - Keywords from Security target
        - Keywords from Certification report
        """

        def st_keywords_may_have_sars(sample: CCCertificate):
            return sample.pdf_data.st_keywords and SAR_DICT_KEY in sample.pdf_data.st_keywords

        def report_keywords_may_have_sars(sample: CCCertificate):
            return sample.pdf_data.report_keywords and SAR_DICT_KEY in sample.pdf_data.report_keywords

        sec_level_sars = SARTransformer._parse_sars_from_security_level_list(cert.security_level)

        if st_keywords_may_have_sars(cert):
            st_dict: dict = cast(dict, cert.pdf_data.st_keywords)
            st_sars = SARTransformer._parse_sar_dict(st_dict[SAR_DICT_KEY], cert.dgst)
        else:
            st_sars = set()

        if report_keywords_may_have_sars(cert):
            report_dict: dict = cast(dict, cert.pdf_data.report_keywords)
            report_sars = SARTransformer._parse_sar_dict(report_dict[SAR_DICT_KEY], cert.dgst)
        else:
            report_sars = set()

        return sec_level_sars, st_sars, report_sars

    @staticmethod
    def _resolve_candidate_conflicts(
        sec_level_candidates: set[SAR], st_candidates: set[SAR], report_candidates: set[SAR], cert_dgst: str
    ) -> set[SAR] | None:
        final_candidates: dict[str, SAR] = {x.family: x for x in sec_level_candidates}
        """
        Given three parameters (SAR candidates from csv scan, ST and cert. report), builds final list of SARs in cert.
        This is done as follows:
        - All SARs from security level are added first
        - Non-conflicting SARs from security target are added as well
        - Non-conflicting SARs from ceritifcation report are added at last

        Note: Conflict means an attempt to add SAR of family (but different level) that is already present in the set.

        :return Set | None: Returns set of SARs or None if empty
        """
        for candidate in st_candidates:
            if candidate.family in final_candidates and candidate != final_candidates[candidate.family]:
                logger.debug(
                    f"Cert {cert_dgst} SAR conflict: Attempting to add {candidate} from ST, conflicts with {final_candidates[candidate.family]}"
                )
            else:
                final_candidates[candidate.family] = candidate

        for candidate in report_candidates:
            if candidate.family in final_candidates and candidate != final_candidates[candidate.family]:
                logger.debug(
                    f"Cert {cert_dgst} SAR conflict: Attempting to add {candidate} from cert. report, conflicts with {final_candidates[candidate.family]}"
                )
            else:
                final_candidates[candidate.family] = candidate

        return set(final_candidates.values()) if final_candidates else None

    @staticmethod
    def _parse_sar_dict(dct: dict[str, dict[str, int]], dgst: str) -> set[SAR]:
        """
        Accepts st_keywords or report_keywords dictionary. Will reconstruct SAR objects from it. Each SAR family can
        appear multiple times in the dictionary (due to conflicts) with different levels. Iterated item will replace
        existing record if:
        - it has higher level than than the current SAR

        Only SARs with recovered level are considered, e.g. ASE_REQ.2 is valid string while ASE_REQ is not.

        :param dct: _description_
        :param dgst: DIgest of the processed certificate.
        :return: _description_
        """
        sars: dict[str, tuple[SAR, int]] = {}
        for sar_class, class_matches in dct.items():
            for sar_string, n_occurences in class_matches.items():
                try:
                    candidate = SAR.from_string(sar_string)
                except ValueError as e:
                    logger.debug(f"Badly formatted SAR string {sar_string}, skipping: {e}")
                    continue

                if candidate.family in sars:
                    logger.debug(
                        f"Cert {dgst} Attempting to add {candidate} while {sars[candidate.family]}  already in SARS"
                    )

                if (candidate.family not in sars) or (
                    candidate.family in sars and candidate.level > sars[candidate.family][0].level
                ):
                    sars[candidate.family] = (candidate, n_occurences)
        return {x[0] for x in sars.values()} if sars else set()

    @staticmethod
    def _parse_sars_from_security_level_list(lst: Iterable[str]) -> set[SAR]:
        sars = set()
        for element in lst:
            try:
                sars.add(SAR.from_string(element))
            except ValueError:
                continue
        return sars
