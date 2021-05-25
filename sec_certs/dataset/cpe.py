from dataclasses import dataclass, field
import logging
import json
from typing import Optional, List, Dict, Tuple, Set, Union, ClassVar
import itertools
import re
from rapidfuzz import process, fuzz
import tempfile
from pathlib import Path
import zipfile
import operator

import sec_certs.helpers as helpers
from sec_certs.serialization import ComplexSerializableType

import pandas as pd
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


@dataclass(init=False)
class CPE(ComplexSerializableType):
    uri: str
    title: str
    version: str
    vendor: str
    item_name: str

    def __init__(self, uri: Optional[str] = None, title: Optional[str] = None):
        self.uri = uri
        self.title = title

        if self.uri:
            self.vendor = ' '.join(self.uri.split(':')[3].split('_'))
            self.item_name = ' '.join(self.uri.split(':')[4].split('_'))
            self.version = self.uri.split(':')[5]

    def __lt__(self, other: 'CPE'):
        return self.title < other.title

    @property
    def serialized_attributes(self) -> List[str]:
        return ['uri', 'title']

    def __hash__(self):
        return hash(self.uri)


def build_cpe_uri_to_title_dict(input_xml_filepath: str, output_filepath: str):
    """
    Will parse CPE XML file into dictionary cpe_uri: cpe_title and dump the dict into json
    """
    logger.info(f'Extracting dictionary cpe_uri:cpe_title from {input_xml_filepath} to {output_filepath}')
    root = ET.parse(input_xml_filepath).getroot()
    dct = {}
    for cpe_item in root.findall('{http://cpe.mitre.org/dictionary/2.0}cpe-item'):
        title = cpe_item.find('{http://cpe.mitre.org/dictionary/2.0}title').text
        cpe_uri = cpe_item.find('{http://scap.nist.gov/schema/cpe-extension/2.3}cpe23-item').attrib['name']
        dct[cpe_uri] = title
    with open(output_filepath, 'w') as handle:
        json.dump(dct, handle, indent=4)


# TODO: Make this ComplexSerializableType
@dataclass
class CPEDataset:
    cpes: Dict[str, CPE]
    vendor_to_versions: Dict[str, Set[str]] = field(init=False)  # Look-up dict cpe_vendor: list of viable versions
    vendor_version_to_cpe: Dict[Tuple[str, str], Set[CPE]] = field(init=False)  # Look-up dict (cpe_vendor, cpe_version): List of viable cpe items
    title_to_cpes: Dict[str, Set[CPE]] = field(init=False) # Look-up dict title: List of cert items
    vendors: Set[str] = field(init=False)

    cpe_xml_basename: ClassVar[str] = 'official-cpe-dictionary_v2.3.xml'
    cpe_url: ClassVar[str] = 'https://nvd.nist.gov/feeds/xml/cpe/dictionary/' + cpe_xml_basename + '.zip'

    def __iter__(self):
        yield from self.cpes.values()

    def __getitem__(self, item: str) -> CPE:
        return self.cpes.__getitem__(item.lower())

    def __setitem__(self, key: str, value: CPE):
        self.cpes.__setitem__(key.lower(), value)

    def __len__(self) -> int:
        return len(self.cpes)

    def __post_init__(self):
        """
        Will build look-up dictionaries that are used for fast matching
        """
        logging.info('CPE dataset: building lookup dictionaries.')
        self.vendor_to_versions = {x.vendor: set() for x in self}
        self.vendor_version_to_cpe = dict()
        self.title_to_cpes = dict()
        self.vendors = set(self.vendor_to_versions.keys())
        for cpe in self:
            self.vendor_to_versions[cpe.vendor].add(cpe.version)
            if (cpe.vendor, cpe.version) not in self.vendor_version_to_cpe:
                self.vendor_version_to_cpe[(cpe.vendor, cpe.version)] = {cpe}
            else:
                self.vendor_version_to_cpe[(cpe.vendor, cpe.version)].add(cpe)
            if cpe.title not in self.title_to_cpes:
                self.title_to_cpes[cpe.title] = {cpe}
            else:
                self.title_to_cpes[cpe.title].add(cpe)

    @classmethod
    def from_json(cls, json_path: Union[str, Path]):
        with Path(json_path).open('r') as handle:
            data = json.load(handle)
        return cls({x: CPE(x, y) for x, y in data.items()})

    def to_json(self, json_path: str):
        with open(json_path, 'w') as handle:
            json.dump({x: y.title for x, y in self.cpes.items()}, handle, indent=4)

    @classmethod
    def from_web(cls):
        with tempfile.TemporaryDirectory() as tmp_dir:
            xml_path = Path(tmp_dir) / cls.cpe_xml_basename
            zip_path = Path(tmp_dir) / (cls.cpe_xml_basename + '.zip')
            helpers.download_file(cls.cpe_url, zip_path)

            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(tmp_dir)

            return cls.from_xml(xml_path)

    @classmethod
    def from_xml(cls, xml_path: Union[str, Path]):
        logger.info('Loading CPE dataset from XML.')
        root = ET.parse(xml_path).getroot()
        dct = {}
        for cpe_item in root.findall('{http://cpe.mitre.org/dictionary/2.0}cpe-item'):
            title = cpe_item.find('{http://cpe.mitre.org/dictionary/2.0}title').text
            cpe_uri = cpe_item.find('{http://scap.nist.gov/schema/cpe-extension/2.3}cpe23-item').attrib['name']
            dct[cpe_uri] = CPE(cpe_uri, title)
        return cls(dct)

    def to_pandas(self):
        if not self.cpes:
            return None
        else:
            columns = list(CPE.__annotations__.keys())
            data = [list(x.__dict__.values()) for x in self]
            df = pd.DataFrame(data, columns=columns)
            df = df.set_index('uri')

        return df

    def get_cpes_from_title(self, title: str) -> List[CPE]:
        return [cpe for cpe in self if cpe.title == title]

    def get_candidate_list_of_vendors(self, cert_vendor: str) -> Optional[List[str]]:
        """
        Will return List of CPE vendors that could match the cert_vendor.
        """
        result = set()
        if not isinstance(cert_vendor, str):
            return None
        lower = cert_vendor.lower()
        if ' / ' in cert_vendor:
            chain = [self.get_candidate_list_of_vendors(x) for x in cert_vendor.split(' / ')]
            chain = [x for x in chain if x]
            return list(set(itertools.chain(*chain)))
        if lower in self.vendors:
            result.add(lower)
        if ' ' in lower and (y := lower.split(' ')[0]) in self.vendors:
            result.add(y)
        if ',' in lower and (y := lower.split(',')[0]) in self.vendors:
            result.add(y)
        if not result:
            return None
        return list(result)

    def get_candidate_vendor_version_pairs(self, cert_candidate_cpe_vendors: List[str], cert_candidate_versions: List[str]) -> Optional[List[Tuple[str, str]]]:
        """
        Given parameters, will return Pairs (cpe_vendor, cpe_version) that should are relevant to a given certificate
        Parameters
        :param cert_candidate_cpe_vendors: list of CPE vendors relevant to a certificate
        :param cert_candidate_versions: List of versions heuristically extracted from the certificate name
        :return: List of tuples (cpe_vendor, cpe_version) that can be used in the lookup table to search the CPE dataset.
        """

        def is_cpe_version_among_cert_versions(cpe_version: str, cert_versions: List[str]) -> bool:
            just_numbers = r'(\d{1,5})(\.\d{1,5})' # TODO: The use of this should be double-checked
            for v in cert_versions:
                if (v.startswith(cpe_version) and re.search(just_numbers, cpe_version)) or cpe_version.startswith(v):
                    return True
            return False

        if not cert_candidate_cpe_vendors:
            return None

        candidate_vendor_version_pairs: List[Tuple[str, str]] = []
        for vendor in cert_candidate_cpe_vendors:
            viable_cpe_versions = self.vendor_to_versions[vendor]
            matched_cpe_versions = [x for x in viable_cpe_versions if is_cpe_version_among_cert_versions(x, cert_candidate_versions)]
            candidate_vendor_version_pairs.extend([(vendor, x) for x in matched_cpe_versions])
        return candidate_vendor_version_pairs

    def get_candidate_cpe_items(self, cert_candidate_cpe_vendors: List[str], cert_candidate_versions: List[str]) -> Optional[List[CPE]]:
        candidate_vendor_version_pairs = self.get_candidate_vendor_version_pairs(cert_candidate_cpe_vendors, cert_candidate_versions)

        if not candidate_vendor_version_pairs:
            return []

        return list(itertools.chain.from_iterable([self.vendor_version_to_cpe[x] for x in candidate_vendor_version_pairs]))

    def get_cpe_matches(self, cert_name: str, cert_candidate_cpe_vendors: List[str], cert_candidate_versions: List[str], relax_version: bool = False, n_max_matches=10, threshold: int = 60) -> Optional[List[Tuple[float, CPE]]]:
        replace_non_letter_non_numbers_with_space = re.compile(r"(?ui)\W")

        def sanitize_matched_string(string: str):
            string = string.replace('®', '').replace('™', '').lower()
            return replace_non_letter_non_numbers_with_space.sub(' ', string)
        candidates = self.get_candidate_cpe_items(cert_candidate_cpe_vendors, cert_candidate_versions)

        sanitized_cert_name = sanitize_matched_string(cert_name)
        reasonable_matches = []
        for c in candidates:
            sanitized_title = sanitize_matched_string(c.title)
            sanitized_item_name = sanitize_matched_string(c.item_name)
            set_match_title = fuzz.token_set_ratio(sanitized_cert_name, sanitized_title)
            partial_match_title = fuzz.partial_ratio(sanitized_cert_name, sanitized_title)
            set_match_item = fuzz.token_set_ratio(sanitized_cert_name, sanitized_item_name)
            partial_match_item = fuzz.partial_ratio(sanitized_cert_name, sanitized_item_name)

            potential = max([set_match_title, partial_match_title, set_match_item, partial_match_item])

            if potential > threshold:
                reasonable_matches.append((potential, c))

        if reasonable_matches:
            reasonable_matches = sorted(reasonable_matches, key=operator.itemgetter(0), reverse=True)

            # possibly filter short titles to avoid false positives
            # reasonable_matches = list(filter(lambda x: len(x[1].item_name) > 4, reasonable_matches))

            return reasonable_matches[:n_max_matches]

        if not reasonable_matches and not relax_version:
            return self.get_cpe_matches(cert_name, cert_candidate_cpe_vendors, ['-'], relax_version=True, n_max_matches=n_max_matches, threshold=threshold)

        return None