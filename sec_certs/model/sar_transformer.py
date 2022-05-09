from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Set, Tuple, cast

from sklearn.base import BaseEstimator, TransformerMixin

from sec_certs.sample.common_criteria import CommonCriteriaCert
from sec_certs.sample.sar import SAR, SAR_DICT_KEY


class SARTransformer(BaseEstimator, TransformerMixin):
    """
    Class for transforming SARs defined in st_keywords and report_keywords dictionaries into SAR objects.
    This class implements sklearn transformer interface, so fit_transform() can be called on it.
    """

    def __init__(self):
        self.sars: Dict[str, Optional[Set[SAR]]] = dict()

    def fit(self, certificates: Iterable[CommonCriteriaCert]) -> SARTransformer:
        self.sars = dict()
        for cert in certificates:
            self.fit_single_cert(cert)
        return self

    def fit_single_cert(self, cert: CommonCriteriaCert):
        def can_have_some_sars(sample: CommonCriteriaCert):
            return sample.pdf_data.st_keywords and SAR_DICT_KEY in sample.pdf_data.st_keywords

        if can_have_some_sars(cert):
            sar_dict: Dict = cast(Dict, cert.pdf_data.st_keywords)
            self.sars[cert.dgst] = self.parse_sar_dict(sar_dict[SAR_DICT_KEY])
        else:
            self.sars[cert.dgst] = None

    def transform(self, certificates: Iterable[CommonCriteriaCert]) -> List[Optional[Set[SAR]]]:
        return [self.transform_single_cert(cert) for cert in certificates]

    def transform_single_cert(self, cert: CommonCriteriaCert) -> Optional[Set[SAR]]:
        try:
            return self.sars[cert.dgst]
        except KeyError:
            raise ValueError(f"The certificate {cert.dgst} was not in the fitted dataset.")

    @staticmethod
    def parse_sar_dict(dct: Dict[str, int]) -> Optional[Set[SAR]]:
        """
        Accepts st_keywords or report_keywords dictionary. Will reconstruct SAR objects from it. Each SAR family can
        appear multiple times in the dictionary (due to conflicts) with different levels. Iterated item will replace
        existing record if:
        - it has more occurences in the text than the currently stored record
        - it has the same number of occurences and higher level than the currently stored record

        Only SARs with recovered level are considered, e.g. ASE_REQ.2 is valid string while ASE_REQ is not.

        :param Dict[str, int] dct: _description_
        :return Optional[Set[SAR]]: _description_
        """
        sars: Dict[str, Tuple[SAR, int]] = dict()
        for sar_string, n_occurences in dct.items():
            if not SAR.is_correctly_formatted(sar_string):
                continue
            candidate = SAR.from_string(sar_string)
            if (
                (candidate.family not in sars)
                or (candidate.family in sars and n_occurences > sars[candidate.family][1])
                or (
                    candidate.family in sars
                    and n_occurences == sars[candidate.family][1]
                    and candidate.level > sars[candidate.family][0].level
                )
            ):
                sars[candidate.family] = (candidate, n_occurences)
        return {x[0] for x in sars.values()} if sars else None
