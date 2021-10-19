import copy
import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional, Final

from dateutil.parser import isoparse

from sec_certs.serialization import ComplexSerializableType
from sec_certs.sample.cpe import CPE

@dataclass(init=False)
class CVE(ComplexSerializableType):
    @dataclass(eq=True)
    class Impact(ComplexSerializableType):
        base_score: float
        severity: str
        explotability_score: float
        impact_score: float

        @classmethod
        def from_nist_dict(cls, dct: Dict):
            """
            Will load Impact from dictionary defined at https://nvd.nist.gov/feeds/json/cve/1.1
            """
            if not dct['impact']:
                return cls(0, '', 0, 0)
            elif 'baseMetricV3' in dct['impact']:
                return cls(dct['impact']['baseMetricV3']['cvssV3']['baseScore'],
                           dct['impact']['baseMetricV3']['cvssV3']['baseSeverity'],
                           dct['impact']['baseMetricV3']['exploitabilityScore'],
                           dct['impact']['baseMetricV3']['impactScore'])
            elif 'baseMetricV2' in dct['impact']:
                return cls(dct['impact']['baseMetricV2']['cvssV2']['baseScore'],
                           dct['impact']['baseMetricV2']['severity'],
                           dct['impact']['baseMetricV2']['exploitabilityScore'],
                           dct['impact']['baseMetricV2']['impactScore'])

    cve_id: str
    vulnerable_cpes: List[str]
    vulnerable_certs: List[str]
    impact: Impact
    published_date: Optional[datetime.datetime]
    tokenized: Optional[str]

    pandas_columns: Final[List[str]] = ('cve_id', 'vulnerable_cpes', 'vulnerable_certs', 'base_score', 'severity',
                                        'explotability_score', 'impact_score', 'published_date', 'description')

    def __init__(self, cve_id: str, vulnerable_cpes: List[str], vulnerable_certs: Optional[List[str]], impact: Impact,
                 published_date: str, tokenized=None):
        super().__init__()
        self.cve_id = cve_id
        self.vulnerable_cpes = vulnerable_cpes

        self.vulnerable_certs = vulnerable_certs
        if not self.vulnerable_certs:
            self.vulnerable_certs = []

        self.impact = impact
        self.published_date = isoparse(published_date)
        self.tokenized = tokenized

    def __hash__(self):
        return hash(self.cve_id)

    def __eq__(self, other):
        if not isinstance(other, CVE):
            return False
        return self.cve_id == other.cve_id

    def __lt__(self, other):
        if not isinstance(other, CVE):
            raise ValueError(f'Cannot compare CVE with {type(other)} type.')
        self_year = int(self.cve_id.split('-')[1])
        self_id = int(self.cve_id.split('-')[2])
        other_year = int(other.cve_id.split('-')[1])
        other_id = int(other.cve_id.split('-')[2])

        return self_year < other_year if self_year != other_year else self_id < other_id

    @property
    def serialized_attributes(self) -> List[str]:
        all_vars = copy.deepcopy(super().serialized_attributes)
        all_vars.remove('tokenized')
        return all_vars

    @classmethod
    def from_nist_dict(cls, dct: Dict) -> 'CVE':
        """
        Will load CVE from dictionary defined at https://nvd.nist.gov/feeds/json/cve/1.1
        """
        def get_vulnerable_cpes_from_nist_dict(dct: Dict) -> List[CPE]:
            def get_vulnerable_cpes_from_node(node: Dict) -> List[CPE]:
                cpe_uris = []
                if 'children' in node:
                    for child in node['children']:
                        cpe_uris += get_vulnerable_cpes_from_node(child)
                if 'cpe_match' in node:
                    lst = node['cpe_match']
                    for x in lst:
                        if x['vulnerable']:
                            cpe_uri = x['cpe23Uri']

                            if 'versionStartIncluding' in x:
                                version_start = ('including', x['versionStartIncluding'])
                            elif 'versionStartExcluding' in x:
                                version_start = ('excluding', x['versionStartExcluding'])
                            else:
                                version_start = None

                            if 'versionEndIncluding' in x:
                                version_end = ('including', x['versionEndIncluding'])
                            elif 'versionEndExcluding' in x:
                                version_end = ('excluding', x['versionEndExcluding'])
                            else:
                                version_end = None

                            cpe_uris.append(CPE(cpe_uri, start_version=version_start, end_version=version_end))

                return cpe_uris

            vulnerable_cpes = []
            for node in dct['configurations']['nodes']:
                vulnerable_cpes.extend(get_vulnerable_cpes_from_node(node))

            return vulnerable_cpes

        cve_id = dct['cve']['CVE_data_meta']['ID']
        impact = cls.Impact.from_nist_dict(dct)
        vulnerable_cpes = get_vulnerable_cpes_from_nist_dict(dct)
        vulnerable_certs = None
        published_date = dct['publishedDate']

        description = dct['cve']['description']['description_data'][0]['value']

        return cls(cve_id, vulnerable_cpes, vulnerable_certs, impact, published_date, description)

    def to_pandas_tuple(self):
        return (self.cve_id, self.vulnerable_cpes, self.vulnerable_certs, self.impact.base_score, self.impact.severity,
                self.impact.explotability_score, self.impact.impact_score, self.published_date)