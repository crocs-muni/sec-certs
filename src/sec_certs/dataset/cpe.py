from __future__ import annotations

import copy
import itertools
import logging
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import ClassVar, Iterator

import pandas as pd

from sec_certs import constants
from sec_certs.dataset.cve import CVEDataset
from sec_certs.dataset.json_path_dataset import JSONPathDataset
from sec_certs.sample.cpe import CPE, cached_cpe
from sec_certs.serialization.json import ComplexSerializableType, serialize
from sec_certs.utils import helpers
from sec_certs.utils.tqdm import tqdm

logger = logging.getLogger(__name__)


class CPEDataset(JSONPathDataset, ComplexSerializableType):
    """
    Dataset of CPE records. Includes look-up dictionaries for fast search.
    """

    CPE_XML_BASENAME: ClassVar[str] = "official-cpe-dictionary_v2.3.xml"
    CPE_URL: ClassVar[str] = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/" + CPE_XML_BASENAME + ".zip"

    def __init__(
        self,
        was_enhanced_with_vuln_cpes: bool,
        cpes: dict[str, CPE],
        json_path: str | Path = constants.DUMMY_NONEXISTING_PATH,
    ):
        self.was_enhanced_with_vuln_cpes = was_enhanced_with_vuln_cpes
        self.cpes = cpes
        self.json_path = Path(json_path)

        self.vendor_to_versions: dict[str, set[str]] = dict()
        self.vendor_version_to_cpe: dict[tuple[str, str], set[CPE]] = dict()
        self.title_to_cpes: dict[str, set[CPE]] = dict()
        self.vendors: set[str] = set()

        self.build_lookup_dicts()

    def __iter__(self) -> Iterator[CPE]:
        yield from self.cpes.values()

    def __getitem__(self, item: str) -> CPE:
        return self.cpes.__getitem__(item.lower())

    def __setitem__(self, key: str, value: CPE) -> None:
        self.cpes.__setitem__(key.lower(), value)

    def __len__(self) -> int:
        return len(self.cpes)

    def __contains__(self, item: CPE) -> bool:
        if not isinstance(item, CPE):
            raise ValueError(f"{item} is not of CPE class")
        return item.uri in self.cpes.keys() and self.cpes[item.uri] == item

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CPEDataset) and self.cpes == other.cpes

    @property
    def serialized_attributes(self) -> list[str]:
        return ["was_enhanced_with_vuln_cpes", "cpes"]

    def build_lookup_dicts(self) -> None:
        """
        Will build look-up dictionaries that are used for fast matching.
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

            if cpe.title:
                if cpe.title not in self.title_to_cpes:
                    self.title_to_cpes[cpe.title] = {cpe}
                else:
                    self.title_to_cpes[cpe.title].add(cpe)

    @classmethod
    def from_web(cls, json_path: str | Path = constants.DUMMY_NONEXISTING_PATH) -> CPEDataset:
        """
        Creates CPEDataset from NIST resources published on-line

        :param Union[str, Path] json_path: Path to store the dataset to
        :return CPEDataset: The resulting dataset
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            xml_path = Path(tmp_dir) / cls.CPE_XML_BASENAME
            zip_path = Path(tmp_dir) / (cls.CPE_XML_BASENAME + ".zip")
            helpers.download_file(cls.CPE_URL, zip_path)

            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(tmp_dir)

            return cls._from_xml(xml_path, json_path)

    @classmethod
    def _from_xml(cls, xml_path: str | Path, json_path: str | Path = constants.DUMMY_NONEXISTING_PATH) -> CPEDataset:
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

        return cls(False, dct, json_path)

    def to_pandas(self) -> pd.DataFrame:
        """
        Turns the dataset into pandas DataFrame. Each CPE record forms a row.

        :return pd.DataFrame: the resulting DataFrame
        """
        df = pd.DataFrame([x.pandas_tuple for x in self], columns=CPE.pandas_columns)
        df = df.set_index("uri")
        return df

    @serialize
    def enhance_with_cpes_from_cve_dataset(self, cve_dset: CVEDataset | str | Path) -> None:
        """
        Some CPEs are present only in the CVEDataset and are missing from the CPE Dataset.
        This method goes through the provided CVEDataset and enriches self with CPEs from
        the CVEDataset.

        :param Union[CVEDataset, str, Path] cve_dset: CVEDataset of a path to it.
        """

        def _adding_condition(
            considered_cpe: CPE,
            vndr_item_lookup: set[tuple[str, str]],
            vndr_item_version_lookup: set[tuple[str, str, str]],
        ) -> bool:
            if (
                considered_cpe.version == constants.CPE_VERSION_NA
                and (considered_cpe.vendor, considered_cpe.item_name) not in vndr_item_lookup
            ):
                return True
            elif (
                considered_cpe.version != constants.CPE_VERSION_NA
                and (considered_cpe.vendor, considered_cpe.item_name, considered_cpe.version)
                not in vndr_item_version_lookup
            ):
                return True
            return False

        if isinstance(cve_dset, (str, Path)):
            cve_dset = CVEDataset.from_json(cve_dset)

        if not isinstance(cve_dset, CVEDataset):
            raise RuntimeError("Conversion of CVE dataset did not work.")
        all_cpes_in_cve_dset = set(itertools.chain.from_iterable(cve.vulnerable_cpes for cve in cve_dset))

        old_len = len(self.cpes)

        # We only enrich if tuple (vendor, item_name) is not already in the dataset
        vendor_item_lookup = {(cpe.vendor, cpe.item_name) for cpe in self}
        vendor_item_version_lookup = {(cpe.vendor, cpe.item_name, cpe.version) for cpe in self}
        for cpe in tqdm(all_cpes_in_cve_dset, desc="Enriching CPE dataset with new CPEs"):
            if _adding_condition(cpe, vendor_item_lookup, vendor_item_version_lookup):
                new_cpe = copy.deepcopy(cpe)
                new_cpe.start_version = None
                new_cpe.end_version = None
                self[new_cpe.uri] = new_cpe
        self.build_lookup_dicts()

        logger.info(f"Enriched the CPE dataset with {len(self.cpes) - old_len} new CPE records.")
        self.was_enhanced_with_vuln_cpes = True
