from __future__ import annotations

import copy
import gzip
import itertools
import logging
import shutil
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar, Iterator

import pandas as pd

import sec_certs.configuration as config_module
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

    def __init__(
        self,
        was_enhanced_with_vuln_cpes: bool = False,
        cpes: dict[str, CPE] = {},
        json_path: str | Path = constants.DUMMY_NONEXISTING_PATH,
        last_update_timestamp: datetime = datetime.fromtimestamp(0),
    ):
        self.was_enhanced_with_vuln_cpes = was_enhanced_with_vuln_cpes
        self.cpes = cpes
        self.json_path = Path(json_path)
        self.last_update_timestamp = last_update_timestamp

        self.vendor_to_versions: dict[str, set[str]] = {}
        self.vendor_version_to_cpe: dict[tuple[str, str], set[CPE]] = {}
        self.title_to_cpes: dict[str, set[CPE]] = {}
        self.vendors: set[str] = set()

        self.build_lookup_dicts()

    def __iter__(self) -> Iterator[CPE]:
        yield from self.cpes.values()

    def __getitem__(self, item: str) -> CPE:
        return self.cpes.__getitem__(item.lower())

    def __setitem__(self, key: str, value: CPE) -> None:
        self.cpes.__setitem__(key.lower(), value)

    def __delitem__(self, key: str) -> None:
        self.cpes.__delitem__[key]

    def __len__(self) -> int:
        return len(self.cpes)

    def __contains__(self, item: CPE) -> bool:
        if not isinstance(item, CPE):
            raise ValueError(f"{item} is not of CPE class")
        return item.uri in self.cpes and self.cpes[item.uri] == item

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CPEDataset) and self.cpes == other.cpes

    @property
    def serialized_attributes(self) -> list[str]:
        return ["last_update_timestamp", "was_enhanced_with_vuln_cpes", "cpes"]

    def build_lookup_dicts(self) -> None:
        """
        Will build look-up dictionaries that are used for fast matching.
        """
        logger.info("CPE dataset: building lookup dictionaries.")
        self.vendor_to_versions = {x.vendor: set() for x in self}
        self.vendor_version_to_cpe = {}
        self.title_to_cpes = {}
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
    def from_dict(cls, dct: dict[str, Any]) -> CPEDataset:
        dct["last_update_timestamp"] = datetime.fromisoformat(dct["last_update_timestamp"])
        return cls(**dct)

    @classmethod
    def from_web(cls, json_path: str | Path = constants.DUMMY_NONEXISTING_PATH) -> CPEDataset:
        """
        Creates CPEDataset from NIST resources published on-line

        :param Union[str, Path] json_path: Path to store the dataset to
        :return CPEDataset: The resulting dataset
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            dset_path = Path(tmp_dir) / "cpe_dataset.json.gz"
            helpers.download_file(
                config_module.config.cpe_latest_snapshot, dset_path, progress_bar_desc="Downloading CPEDataset from web"
            )
            dset = cls.from_json(dset_path, is_compressed=True)

        dset.json_path = json_path
        dset.to_json()
        return dset

    def enhance_with_nvd_data(self, nvd_data: dict[Any, Any]) -> None:
        self.last_update_timestamp = datetime.fromisoformat(nvd_data["timestamp"])
        cpes_to_deprecate: set[str] = set()

        for cpe in nvd_data["products"]:
            if cpe["cpe"]["deprecated"]:
                cpes_to_deprecate.add(cpe["cpe"]["cpeNameId"])
            else:
                new_cpe = CPE.from_nvd_dict(cpe["cpe"])
                self.cpes[new_cpe.uri] = new_cpe

        uris_to_delete = self._find_uris_for_ids(cpes_to_deprecate)
        for uri in uris_to_delete:
            del self[uri]

        self.build_lookup_dicts()

    def _find_uris_for_ids(self, ids: set[str]) -> set[str]:
        return {x.uri for x in self if x.uri in ids}

    def to_pandas(self) -> pd.DataFrame:
        """
        Turns the dataset into pandas DataFrame. Each CPE record forms a row.

        :return pd.DataFrame: the resulting DataFrame
        """
        return pd.DataFrame([x.pandas_tuple for x in self], columns=CPE.pandas_columns).set_index("uri")

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
            if (
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
