from typing import Dict, Iterable, List, Optional, Set, Tuple

from sec_certs.sample.common_criteria import CommonCriteriaCert
from sec_certs.sample.sar import SAR, SAR_DICT_KEY


class SARParser:
    def __init__(self):
        self.sars: Dict[str, Optional[Set[SAR]]] = dict()

    def fit(self, certificates: Iterable[CommonCriteriaCert]) -> "SARParser":
        self.sars = dict()
        for cert in certificates:
            self.fit_single_cert(cert)
        return self

    def fit_single_cert(self, cert: CommonCriteriaCert):
        def can_have_some_sars(sample: CommonCriteriaCert):
            return sample.pdf_data.st_keywords and SAR_DICT_KEY in sample.pdf_data.st_keywords

        self.sars[cert.dgst] = (
            self.parse_sar_dict(cert.pdf_data.st_keywords[SAR_DICT_KEY]) if can_have_some_sars(cert) else None  # type: ignore
        )

    def predict(self, certificates: Iterable[CommonCriteriaCert]) -> List[Optional[Set[SAR]]]:
        return [self.predict_single_cert(cert) for cert in certificates]

    def predict_single_cert(self, cert: CommonCriteriaCert) -> Optional[Set[SAR]]:
        try:
            return self.sars[cert.dgst]
        except KeyError:
            raise ValueError(f"The certificate {cert.dgst} was not in the fitted dataset.")

    @staticmethod
    def parse_sar_dict(dct: Dict[str, int]) -> Optional[Set[SAR]]:
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
