from dataclasses import dataclass, field
import logging
import json
from typing import Optional, List, Dict, Tuple, Set, Union, ClassVar
import itertools
import re
from rapidfuzz import fuzz
import tempfile
from pathlib import Path
import zipfile
import operator
import tqdm

import sec_certs.helpers as helpers
from sec_certs.sample.cpe import CPE
from sec_certs.dataset.cve import CVEDataset

import pandas as pd
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


# TODO: Make this ComplexSerializableType
@dataclass
class CPEDataset:
    cpes: Dict[str, CPE]
    vendor_to_versions: Dict[str, Set[str]] = field(init=False)  # Look-up dict cpe_vendor: list of viable versions
    vendor_version_to_cpe: Dict[Tuple[str, str], Set[CPE]] = field(init=False)  # Look-up dict (cpe_vendor, cpe_version): List of viable cpe items
    title_to_cpes: Dict[str, Set[CPE]] = field(init=False)  # Look-up dict title: List of cert items
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

    def __contains__(self, item: CPE) -> bool:
        if not isinstance(item, CPE):
            raise ValueError(f'{item} is not of CPE class')
        return item.uri in self.cpes.keys()

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
            columns = CPE.pandas_columns
            data = [x.pandas_tuple for x in self]
            df = pd.DataFrame(data, columns=columns)
            df = df.set_index('uri')

        return df

    # TODO: This should have some usage. Being called prior to automatic CPE matching
    def enhance_with_cpes_from_cve_dataset(self, cve_dset: Union[CVEDataset, str, Path]):
        if isinstance(cve_dset, (str, Path)):
            cve_dset = CVEDataset.from_json(cve_dset)

        all_cpes_in_cve_dset = set(itertools.chain.from_iterable([cve.vulnerable_cpes for cve in cve_dset]))

        old_len = len(self.cpes)

        for cpe in tqdm.tqdm(all_cpes_in_cve_dset, desc='Enriching CPE dataset with new CPEs'):
            if cpe not in self:
                self[cpe.uri] = cpe

        logger.info(f'Enriched the CPE dataset with {len(self.cpes) - old_len} new CPE records.')
