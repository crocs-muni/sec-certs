import copy
import itertools
import logging
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import InitVar, dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Dict, Iterator, List, Set, Tuple, Union, cast

import pandas as pd

from sec_certs import constants, helpers
from sec_certs.dataset.cve import CVEDataset
from sec_certs.sample.cpe import CPE, cached_cpe
from sec_certs.serialization.json import ComplexSerializableType, serialize

logger = logging.getLogger(__name__)


@dataclass
class CPEDataset(ComplexSerializableType):
    """
    Dataset of CPE records. Includes look-up dictionaries for fast search.
    """

    was_enhanced_with_vuln_cpes: bool
    json_path: Path
    cpes: Dict[str, CPE]
    vendor_to_versions: Dict[str, Set[str]] = field(
        init=False, default_factory=dict
    )  # Look-up dict cpe_vendor: list of viable versions
    vendor_version_to_cpe: Dict[Tuple[str, str], Set[CPE]] = field(
        init=False, default_factory=dict
    )  # Look-up dict (cpe_vendor, cpe_version): List of viable cpe items
    title_to_cpes: Dict[str, Set[CPE]] = field(
        init=False, default_factory=dict
    )  # Look-up dict title: List of cert items
    vendors: Set[str] = field(init=False, default_factory=set)

    init_lookup_dicts: InitVar[bool] = True
    cpe_xml_basename: ClassVar[str] = "official-cpe-dictionary_v2.3.xml"
    cpe_url: ClassVar[str] = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/" + cpe_xml_basename + ".zip"

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
    def serialized_attributes(self) -> List[str]:
        return ["was_enhanced_with_vuln_cpes", "json_path", "cpes"]

    def __post_init__(self, init_lookup_dicts: bool):
        if init_lookup_dicts:
            self.build_lookup_dicts()

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
    def from_web(cls, json_path: Union[str, Path], init_lookup_dicts: bool = True) -> "CPEDataset":
        """
        Creates CPEDataset from NIST resources published on-line

        :param Union[str, Path] json_path: Path to store the dataset to
        :param bool init_lookup_dicts: If dictionaries for fast matching should be computed, defaults to True
        :return CPEDataset: The resulting dataset
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            xml_path = Path(tmp_dir) / cls.cpe_xml_basename
            zip_path = Path(tmp_dir) / (cls.cpe_xml_basename + ".zip")
            helpers.download_file(cls.cpe_url, zip_path)

            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(tmp_dir)

            return cls._from_xml(xml_path, json_path, init_lookup_dicts)

    @classmethod
    def _from_xml(
        cls, xml_path: Union[str, Path], json_path: Union[str, Path], init_lookup_dicts: bool = True
    ) -> "CPEDataset":
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

        return cls(False, Path(json_path), dct, init_lookup_dicts)

    @classmethod
    def from_json(cls, input_path: Union[str, Path]) -> "CPEDataset":
        """
        Loads dataset from json

        :param Union[str, Path] input_path: Path to the serialized json dataset
        :return CPEDataset: the resulting dataset.
        """
        dset = cast("CPEDataset", ComplexSerializableType.from_json(input_path))
        dset.json_path = Path(input_path)
        return dset

    @classmethod
    def from_dict(cls, dct: Dict[str, Any], init_lookup_dicts: bool = True) -> "CPEDataset":
        """
        Loads dataset from dictionary.

        :param Dict[str, Any] dct: Dictionary that holds the dataset
        :param bool init_lookup_dicts: Whether look-up dicts should be computed as a part of initialization, defaults to True
        :return CPEDataset: the resulting dataset.
        """
        return cls(dct["was_enhanced_with_vuln_cpes"], Path("../"), dct["cpes"], init_lookup_dicts)

    def to_pandas(self) -> pd.DataFrame:
        """
        Turns the dataset into pandas DataFrame. Each CPE record forms a row.

        :return pd.DataFrame: the resulting DataFrame
        """
        df = pd.DataFrame([x.pandas_tuple for x in self], columns=CPE.pandas_columns)
        df = df.set_index("uri")
        return df

    @serialize
    def enhance_with_cpes_from_cve_dataset(self, cve_dset: Union[CVEDataset, str, Path]) -> None:
        """
        Some CPEs are present only in the CVEDataset and are missing from the CPE Dataset.
        This method goes through the provided CVEDataset and enriches self with CPEs from
        the CVEDataset.

        :param Union[CVEDataset, str, Path] cve_dset: CVEDataset of a path to it.
        """

        def _adding_condition(
            considered_cpe: CPE,
            vndr_item_lookup: Set[Tuple[str, str]],
            vndr_item_version_lookup: Set[Tuple[str, str, str]],
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
        all_cpes_in_cve_dset = set(itertools.chain.from_iterable([cve.vulnerable_cpes for cve in cve_dset]))

        old_len = len(self.cpes)

        # We only enrich if tuple (vendor, item_name) is not already in the dataset
        vendor_item_lookup = {(cpe.vendor, cpe.item_name) for cpe in self}
        vendor_item_version_lookup = {(cpe.vendor, cpe.item_name, cpe.version) for cpe in self}
        for cpe in helpers.tqdm(all_cpes_in_cve_dset, desc="Enriching CPE dataset with new CPEs"):
            if _adding_condition(cpe, vendor_item_lookup, vendor_item_version_lookup):
                new_cpe = copy.deepcopy(cpe)
                new_cpe.start_version = None
                new_cpe.end_version = None
                self[new_cpe.uri] = new_cpe
        self.build_lookup_dicts()

        logger.info(f"Enriched the CPE dataset with {len(self.cpes) - old_len} new CPE records.")
        self.was_enhanced_with_vuln_cpes = True
