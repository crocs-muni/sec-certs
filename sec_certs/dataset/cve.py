from dataclasses import dataclass, field
from typing import Dict, List,  Optional, Union, ClassVar
import copy
import datetime
from pathlib import Path
import tempfile
import zipfile
import logging
import glob
import tqdm
import json

from sec_certs.parallel_processing import process_parallel
import sec_certs.constants as constants
import sec_certs.helpers as helpers
from sec_certs.serialization import ComplexSerializableType, CustomJSONDecoder, CustomJSONEncoder
from sec_certs.configuration import config

logger = logging.getLogger(__name__)


@dataclass(eq=True, frozen=True)
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
    impact: Impact

    @classmethod
    def from_nist_dict(cls, dct: Dict) -> 'CVE':
        """
        Will load CVE from dictionary defined at https://nvd.nist.gov/feeds/json/cve/1.1
        """
        def get_vulnerable_cpes_from_nist_dict(dct: Dict) -> List[str]:
            def get_vulnerable_cpes_from_node(node: Dict) -> List[str]:
                cpe_uris = []
                if 'children' in node:
                    for child in node['children']:
                        cpe_uris += get_vulnerable_cpes_from_node(child)
                if 'cpe_match' in node:
                    lst = node['cpe_match']
                    for x in lst:
                        if x['vulnerable']:
                            cpe_uris.append(x['cpe23Uri'])
                return cpe_uris

            vulnerable_cpes = []
            for node in dct['configurations']['nodes']:
                vulnerable_cpes.extend(get_vulnerable_cpes_from_node(node))

            return vulnerable_cpes

        cve_id = dct['cve']['CVE_data_meta']['ID']
        impact = cls.Impact.from_nist_dict(dct)
        vulnerable_cpes = get_vulnerable_cpes_from_nist_dict(dct)

        return CVE(cve_id, vulnerable_cpes, impact)


@dataclass(eq=True)
class CVEDataset(ComplexSerializableType):
    cves: Dict[str, CVE]
    cpes_to_cve_lookup: Dict[str, List[str]] = field(init=False)

    cve_url: ClassVar[str] = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-'

    @property
    def serialized_attributes(self) -> List[str]:
        return ['cves']

    def __post_init__(self):
        self.cpes_to_cve_lookup = dict()
        for cve in self:
            for cpe in cve.vulnerable_cpes:
                if not cpe in self.cpes_to_cve_lookup:
                    self.cpes_to_cve_lookup[cpe] = [cve.cve_id]
                else:
                    self.cpes_to_cve_lookup[cpe].append(cve.cve_id)

    def __iter__(self):
        yield from self.cves.values()

    def __getitem__(self, item: str) -> CVE:
        return self.cves.__getitem__(item.lower())

    def __setitem__(self, key: str, value: CVE):
        self.cves.__setitem__(key.lower(), value)

    def __len__(self) -> int:
        return len(self.cves)

    def download_cves(self, output_path: str, start_year: int, end_year: int):
        output_path = Path(output_path)
        if not output_path.exists:
            output_path.mkdir()

        urls = [self.cve_url + str(x) + '.json.zip' for x in range(start_year, end_year + 1)]

        logger.info(f'Identified {len(urls)} CVE files to fetch from nist.gov. Downloading them into {output_path}')
        with tempfile.TemporaryDirectory() as tmp_dir:
            outpaths = [Path(tmp_dir) / Path(x).name.rstrip('.zip') for x in urls]
            responses = list(zip(*helpers.download_parallel(list(zip(urls, outpaths)), num_threads=config.n_threads)))[1]

            for o, u, r in zip(outpaths, urls, responses):
                if r == constants.RESPONSE_OK:
                    with zipfile.ZipFile(o, 'r') as zip_handle:
                        zip_handle.extractall(output_path)
                else:
                    logger.info(f'Failed to download from {u}, got status code {r}')

    @classmethod
    def from_nist_json(cls, input_path: str) -> 'CVEDataset':
        with Path(input_path).open('r') as handle:
            data = json.load(handle)
        cves = [CVE.from_nist_dict(x) for x in data['CVE_Items']]
        return cls({x.cve_id: x for x in cves})

    @classmethod
    def from_web(cls, start_year: int = 2002, end_year: int = datetime.datetime.now().year):
        logger.info(f'Building CVE dataset from nist.gov website.')
        with tempfile.TemporaryDirectory() as tmp_dir:
            cls.download_cves(tmp_dir, start_year, end_year)
            json_files = glob.glob(tmp_dir + '/*.json')

            all_cves = dict()
            logger.info(f'Downloaded required resources. Building CVEDataset from jsons.')
            results = process_parallel(cls.from_nist_json, json_files, config.n_threads, use_threading=False)
            for r in results:
                all_cves.update(r.cves)
        return cls(all_cves)

    def to_json(self, output_path: str):
        with Path(output_path).open('w') as handle:
            json.dump(self, handle, indent=4, cls=CustomJSONEncoder, ensure_ascii=False)

    @classmethod
    def from_json(cls, input_path: Union[str, Path]):
        with Path(input_path).open('r') as handle:
            dset = json.load(handle, cls=CustomJSONDecoder)
        return dset

    def get_cves_for_cpe(self, cpe_uri: str) -> Optional[List[str]]:
        if not isinstance(cpe_uri, str):
            return None
        return self.cpes_to_cve_lookup.get(cpe_uri, None)
