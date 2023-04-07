from __future__ import annotations

import collections
import glob
import itertools
import json
import logging
import shutil
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

import numpy as np
import pandas as pd

import sec_certs.configuration as config_module
from sec_certs import constants
from sec_certs.dataset.json_path_dataset import JSONPathDataset
from sec_certs.sample.cpe import CPE, cached_cpe
from sec_certs.sample.cve import CVE
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils import helpers
from sec_certs.utils.parallel_processing import process_parallel
from sec_certs.utils.tqdm import tqdm

logger = logging.getLogger(__name__)


class CVEDataset(JSONPathDataset, ComplexSerializableType):
    CVE_URL: ClassVar[str] = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"
    CPE_MATCH_FEED_URL: ClassVar[str] = "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip"

    def __init__(
        self,
        cves: dict[str, CVE] = {},
        json_path: str | Path = constants.DUMMY_NONEXISTING_PATH,
        last_update_timestamp: datetime = datetime.fromtimestamp(0),
    ):
        self.cves = cves
        self.json_path = Path(json_path)
        self.cpe_to_cve_ids_lookup: dict[str, set[str]] = {}
        self.cves_with_vulnerable_configurations: list[CVE] = []
        self.last_update_timestamp = last_update_timestamp

    @property
    def serialized_attributes(self) -> list[str]:
        return ["cves"]

    def __iter__(self):
        yield from self.cves.values()

    def __getitem__(self, item: str) -> CVE:
        return self.cves.__getitem__(item.upper())

    def __setitem__(self, key: str, value: CVE):
        self.cves.__setitem__(key.lower(), value)

    def __len__(self) -> int:
        return len(self.cves)

    def __eq__(self, other: object):
        return isinstance(other, CVEDataset) and self.cves == other.cves

    @classmethod
    def from_web(cls, json_path: str | Path = constants.DUMMY_NONEXISTING_PATH) -> CVEDataset:
        """
        Creates CVEDataset from NIST resources published on-line

        :param Union[str, Path] json_path: Path to store the dataset to
        :return CVEDataset: The resulting dataset
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            dset_path = Path(tmp_dir) / "cve_dataset.json.gz"
            helpers.download_file(
                config_module.config.cve_latest_snapshot, dset_path, progress_bar_desc="Downloading CVEDataset from web"
            )
            dset = cls.from_json(dset_path, is_compressed=True)

        dset.json_path = json_path
        dset.to_json()
        return dset

    def _get_cves_with_criteria_configurations(self) -> None:
        """
        Method filters the subset of CVE dataset thah contain at least one CPE configuration in the CVE.
        """
        self.cves_with_vulnerable_configurations = [cve for cve in self if cve.vulnerable_cpe_configurations]

    def build_lookup_dict(
        self,
        cpe_match_dict: dict,
        limit_to_cpes: set[CPE],
    ):
        """
        Builds look-up dictionary CPE -> Set[CVE] and filter the CVEs which contain CPE configurations.
        """
        self.cpe_to_cve_ids_lookup = dict.fromkeys([x.uri for x in limit_to_cpes], set())

        cve: CVE
        for cve in tqdm(self, desc="Building-up lookup dictionaries for fast CVE matching"):
            vulnerable_cpes = set(
                itertools.chain.from_iterable([cpe_match_dict[x]["matches"] for x in cve.vulnerable_criteria])
            )
            if not cve.vulnerable_criteria_configurations and not any(x in limit_to_cpes for x in vulnerable_cpes):
                continue

            for cpe in vulnerable_cpes:
                self.cpe_to_cve_ids_lookup[cpe.uri].add(cve.cve_id)

        self._get_cves_with_criteria_configurations()

    def _get_cve_ids_for_cpe_uri(self, cpe_uri: str) -> set[str]:
        # TODO: Refactor me
        return self.cpe_to_cve_ids_lookup.get(cpe_uri, set())

    def _get_cves_from_exactly_matched_cpes(self, cpe_uris: set[str]) -> set[str]:
        # TODO: Refactor me
        return set(itertools.chain.from_iterable([self._get_cve_ids_for_cpe_uri(cpe_uri) for cpe_uri in cpe_uris]))

    def _get_cves_from_cpe_configurations(self, cpe_uris: set[str]) -> set[str]:
        # TODO: refactor me
        return {
            cve.cve_id
            for cve in self.cves_with_vulnerable_configurations
            if any(configuration.matches(cpe_uris) for configuration in cve.vulnerable_cpe_configurations)
        }

    def get_cves_from_matched_cpes(self, cpe_uris: set[str]) -> set[str]:
        # TODO: refactor me
        """
        Method returns the set of CVEs which are matched to the set of CPEs.
        First are matched the classic CPEs to CVEs with lookup dict and then are matched the
        'AND' type CPEs containing platform.
        """
        return {
            *self._get_cves_from_exactly_matched_cpes(cpe_uris),
            *self._get_cves_from_cpe_configurations(cpe_uris),
        }

    def filter_related_cpes(self, relevant_cpes: set[CPE]):
        # TODO: Refactor me
        """
        Since each of the CVEs is related to many CPEs, the dataset size explodes (serialized). For certificates,
        only CPEs within sample dataset are relevant. This function modifies all CVE elements. Specifically, it
        deletes all CPE records unless they are part of relevant_cpe_uris.
        :param relevant_cpes: List of relevant CPEs to keep in CVE dataset.
        """
        total_deleted_cpes = 0
        cve_ids_to_delete = []
        for cve in self:
            n_cpes_orig = len(cve.vulnerable_cpes)
            cve.vulnerable_cpes = [x for x in cve.vulnerable_cpes if x in relevant_cpes]
            cve.vulnerable_cpe_configurations = [
                x
                for x in cve.vulnerable_cpe_configurations
                if x.platform.uri in relevant_cpes and any(y.uri in relevant_cpes for y in x.cpes)
            ]

            total_deleted_cpes += n_cpes_orig - len(cve.vulnerable_cpes)
            if not cve.vulnerable_cpes:
                cve_ids_to_delete.append(cve.cve_id)

        for cve_id in cve_ids_to_delete:
            del self.cves[cve_id]
        logger.info(
            f"Totally deleted {total_deleted_cpes} irrelevant CPEs and {len(cve_ids_to_delete)} CVEs from CVEDataset."
        )

    def to_pandas(self) -> pd.DataFrame:
        df = pd.DataFrame([x.pandas_tuple for x in self], columns=CVE.pandas_columns)
        df.cwe_ids = df.cwe_ids.map(lambda x: x if x else np.nan)
        return df.set_index("cve_id")

    def enhance_with_nvd_data(self, data: dict[str, Any]) -> None:
        self.last_update_timestamp = datetime.fromisoformat(data["timestamp"])
        for vuln in data["vulnerabilities"]:
            # https://nvd.nist.gov/vuln/vulnerability-status#divNvdStatus
            if vuln["cve"]["vulnStatus"] in {"Analyzed", "Modified"}:
                cve = CVE.from_nist_dict(vuln["cve"])
                self[cve.cve_id] = cve
