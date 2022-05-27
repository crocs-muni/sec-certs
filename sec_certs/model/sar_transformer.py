from __future__ import annotations

import logging
from typing import Dict, Iterable, List, Optional, Set, Tuple, cast

from sklearn.base import BaseEstimator, TransformerMixin

from sec_certs.sample.common_criteria import CommonCriteriaCert
from sec_certs.sample.sar import SAR, SAR_DICT_KEY

logger = logging.getLogger(__name__)


# TODO: Right now we ignore number of ocurrences for final SAR selection. If we keep it this way, we can discard that variable
class SARTransformer(BaseEstimator, TransformerMixin):
    """
    Class for transforming SARs defined in st_keywords and report_keywords dictionaries into SAR objects.
    This class implements sklearn transformer interface, so fit_transform() can be called on it.
    """

    def fit(self, certificates: Iterable[CommonCriteriaCert]) -> SARTransformer:
        """
        Just returns self, no fitting needed

        :param Iterable[CommonCriteriaCert] certificates: Unused parameter
        :return SARTransformer: return self
        """
        return self

    def transform(self, certificates: Iterable[CommonCriteriaCert]) -> List[Optional[Set[SAR]]]:
        """
        Just a wrapper around transform_single_cert() called on an iterable of CommonCriteriaCert.

        :param Iterable[CommonCriteriaCert] certificates: Iterable of CommonCriteriaCert objects to perform the extraction on.
        :return List[Optional[Set[SAR]]]: Returns List of results from transform_single_cert().
        """
        return [self.transform_single_cert(cert) for cert in certificates]

    def transform_single_cert(self, cert: CommonCriteriaCert) -> Optional[Set[SAR]]:
        """
        Given CommonCriteriaCert, will transform SAR keywords extracted from txt files
        into a set of SAR objects. Also handles extractin of correct SAR levels, duplicities and filtering.
        Uses three sources: CSV scan, security target, and certification report.
        The caller should assure that the certificates have the keywords extracted.

        :param CommonCriteriaCert cert: Certificate to extract SARs from
        :return Optional[Set[SAR]]: Set of SARs, None if none were identified.
        """
        sec_level_candidates, st_candidates, report_candidates = self._collect_sar_candidates_from_all_sources(cert)
        return self._resolve_candidate_conflicts(sec_level_candidates, st_candidates, report_candidates, cert.dgst)

    @staticmethod
    def _collect_sar_candidates_from_all_sources(cert: CommonCriteriaCert) -> Tuple[Set[SAR], Set[SAR], Set[SAR]]:
        """
        Parses SARs from three distinct sources and returns the results as a three tuple:
        - Security level from CSV scan
        - Keywords from Security target
        - Keywords from Certification report
        """

        def st_keywords_may_have_sars(sample: CommonCriteriaCert):
            return sample.pdf_data.st_keywords and SAR_DICT_KEY in sample.pdf_data.st_keywords

        def report_keywords_may_have_sars(sample: CommonCriteriaCert):
            return sample.pdf_data.report_keywords and SAR_DICT_KEY in sample.pdf_data.report_keywords

        sec_level_sars = SARTransformer._parse_sars_from_security_level_list(cert.security_level)

        if st_keywords_may_have_sars(cert):
            st_dict: Dict = cast(Dict, cert.pdf_data.st_keywords)
            st_sars = SARTransformer._parse_sar_dict(st_dict[SAR_DICT_KEY], cert.dgst)
        else:
            st_sars = set()

        if report_keywords_may_have_sars(cert):
            report_dict: Dict = cast(Dict, cert.pdf_data.report_keywords)
            report_sars = SARTransformer._parse_sar_dict(report_dict[SAR_DICT_KEY], cert.dgst)
        else:
            report_sars = set()

        return sec_level_sars, st_sars, report_sars

    @staticmethod
    def _resolve_candidate_conflicts(
        sec_level_candidates: Set[SAR], st_candidates: Set[SAR], report_candidates: Set[SAR], cert_dgst: str
    ) -> Optional[Set[SAR]]:
        final_candidates: Dict[str, SAR] = {x.family: x for x in sec_level_candidates}
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
    def _parse_sar_dict(dct: Dict[str, int], dgst: str) -> Set[SAR]:
        """
        Accepts st_keywords or report_keywords dictionary. Will reconstruct SAR objects from it. Each SAR family can
        appear multiple times in the dictionary (due to conflicts) with different levels. Iterated item will replace
        existing record if:
        - it has higher level than than the current SAR

        Only SARs with recovered level are considered, e.g. ASE_REQ.2 is valid string while ASE_REQ is not.

        :param Dict[str, int] dct: _description_
        :return Optional[Set[SAR]]: _description_
        """
        sars: Dict[str, Tuple[SAR, int]] = dict()
        for sar_string, n_occurences in dct.items():
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
    def _parse_sars_from_security_level_list(lst: Iterable[str]) -> Set[SAR]:
        sars = set()
        for element in lst:
            try:
                sars.add(SAR.from_string(element))
            except ValueError:
                continue
        return sars
