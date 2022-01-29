import itertools
import logging
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Dict, List, Set, Tuple, Union

import pandas as pd

import sec_certs.helpers as helpers
from sec_certs.dataset.cve import CVEDataset
from sec_certs.sample.cpe import CPE, cached_cpe
from sec_certs.serialization.json import ComplexSerializableType, serialize

logger = logging.getLogger(__name__)


@dataclass
class CPEDataset(ComplexSerializableType):
    was_enhanced_with_vuln_cpes: bool
    json_path: Path
    cpes: Dict[str, CPE]
    vendor_to_versions: Dict[str, Set[str]] = field(init=False)  # Look-up dict cpe_vendor: list of viable versions
    vendor_version_to_cpe: Dict[Tuple[str, str], Set[CPE]] = field(
        init=False
    )  # Look-up dict (cpe_vendor, cpe_version): List of viable cpe items
    title_to_cpes: Dict[str, Set[CPE]] = field(init=False)  # Look-up dict title: List of cert items
    vendors: Set[str] = field(init=False)

    cpe_xml_basename: ClassVar[str] = "official-cpe-dictionary_v2.3.xml"
    cpe_url: ClassVar[str] = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/" + cpe_xml_basename + ".zip"

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
            raise ValueError(f"{item} is not of CPE class")
        return item.uri in self.cpes.keys()

    @property
    def serialized_attributes(self) -> List[str]:
        return ["was_enhanced_with_vuln_cpes", "json_path", "cpes"]

    def __post_init__(self):
        """
        Will build look-up dictionaries that are used for fast matching
        """
        logger.info("CPE dataset: building lookup dictionaries.")
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
    def from_web(cls, json_path: Union[str, Path]):
        with tempfile.TemporaryDirectory() as tmp_dir:
            xml_path = Path(tmp_dir) / cls.cpe_xml_basename
            zip_path = Path(tmp_dir) / (cls.cpe_xml_basename + ".zip")
            helpers.download_file(cls.cpe_url, zip_path)

            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(tmp_dir)

            return cls.from_xml(xml_path, json_path)

    @classmethod
    def from_xml(cls, xml_path: Union[str, Path], json_path: Union[str, Path]):
        logger.info("Loading CPE dataset from XML.")
        root = ET.parse(xml_path).getroot()
        dct = {}
        for cpe_item in root.findall("{http://cpe.mitre.org/dictionary/2.0}cpe-item"):
            found_title = cpe_item.find("{http://cpe.mitre.org/dictionary/2.0}title")
            if found_title is None:
                raise RuntimeError(
                    "Title is not found during building CPE dataset from xml - this should not be happening"
                )
            title = found_title.text

            found_cpe_uri = cpe_item.find("{http://scap.nist.gov/schema/cpe-extension/2.3}cpe23-item")
            if found_cpe_uri is None:
                raise RuntimeError(
                    "CPE uri is not found during building CPE dataset from xml - this should not be happening"
                )
            cpe_uri = found_cpe_uri.attrib["name"]

            dct[cpe_uri] = cached_cpe(cpe_uri, title)
        return cls(False, Path(json_path), dct)

    @classmethod
    def from_json(cls, input_path: Union[str, Path]):
        dset = ComplexSerializableType.from_json(input_path)
        dset.json_path = input_path
        return dset

    @classmethod
    def from_dict(cls, dct: Dict):
        return cls(dct["was_enhanced_with_vuln_cpes"], Path("../"), dct["cpes"])

    def to_pandas(self):
        df = pd.DataFrame([x.pandas_tuple for x in self], columns=CPE.pandas_columns)
        df = df.set_index("uri")
        return df

    @serialize
    def enhance_with_cpes_from_cve_dataset(self, cve_dset: Union[CVEDataset, str, Path]):
        if isinstance(cve_dset, (str, Path)):
            cve_dset = CVEDataset.from_json(cve_dset)

        if not isinstance(cve_dset, CVEDataset):
            raise RuntimeError("Conversion of CVE dataset did not work.")
        all_cpes_in_cve_dset = set(itertools.chain.from_iterable([cve.vulnerable_cpes for cve in cve_dset]))

        old_len = len(self.cpes)

        for cpe in helpers.tqdm(all_cpes_in_cve_dset, desc="Enriching CPE dataset with new CPEs"):
            if cpe not in self:
                self[cpe.uri] = cpe

        logger.info(f"Enriched the CPE dataset with {len(self.cpes) - old_len} new CPE records.")
        self.was_enhanced_with_vuln_cpes = True
