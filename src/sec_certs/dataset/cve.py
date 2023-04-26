from __future__ import annotations

import itertools
import logging
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

import numpy as np
import pandas as pd

import sec_certs.configuration as config_module
from sec_certs import constants
from sec_certs.dataset.json_path_dataset import JSONPathDataset
from sec_certs.sample.cpe import CPE
from sec_certs.sample.cve import CVE
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils import helpers
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
        self._cpe_uri_to_cve_ids_lookup: dict[str, set[str]] = {}
        self._cves_with_vulnerable_configurations: list[CVE] = []
        self.last_update_timestamp = last_update_timestamp

    def __iter__(self):
        yield from self.cves.values()

    def __getitem__(self, item: str) -> CVE:
        return self.cves.__getitem__(item.upper())

    def __setitem__(self, key: str, value: CVE):
        self.cves.__setitem__(key.upper(), value)

    def __len__(self) -> int:
        return len(self.cves)

    def __eq__(self, other: object):
        return isinstance(other, CVEDataset) and self.cves == other.cves

    @property
    def serialized_attributes(self) -> list[str]:
        return ["last_update_timestamp", "cves"]

    @classmethod
    def from_dict(cls, dct: dict[str, Any]) -> CVEDataset:
        dct["last_update_timestamp"] = datetime.fromisoformat(dct["last_update_timestamp"])
        return cls(**dct)

    @property
    def look_up_dicts_built(self) -> bool:
        return bool(self._cpe_uri_to_cve_ids_lookup)

    @classmethod
    def from_web(cls, json_path: str | Path = constants.DUMMY_NONEXISTING_PATH) -> CVEDataset:
        """
        Creates CVEDataset from NIST resources published on-line

        :param Union[str, Path] json_path: Path to store the dataset to
        :return CVEDataset: The resulting dataset
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            dset_path = Path(tmp_dir) / "cve_dataset.json.gz"
            if (
                not helpers.download_file(
                    config_module.config.cve_latest_snapshot,
                    dset_path,
                    progress_bar_desc="Downloading CVEDataset from web",
                )
                == constants.RESPONSE_OK
            ):
                raise RuntimeError(f"Could not download CVEDataset from {config_module.config.cve_latest_snapshot}.")
            dset = cls.from_json(dset_path, is_compressed=True)

        dset.json_path = json_path
        dset.to_json()
        return dset

    def _get_cves_with_criteria_configurations(self) -> None:
        """
        Method filters the subset of CVE dataset thah contain at least one CPE criteria configuration in the CVE.
        """
        self._cves_with_vulnerable_configurations = [cve for cve in self if cve.vulnerable_criteria_configurations]

    def _expand_criteria_configurations(self, matching_dict: dict, relevant_cpe_uris: set[str] | None = None) -> None:
        indices_to_delete = []
        cve: CVE
        for index, cve in enumerate(
            tqdm(self._cves_with_vulnerable_configurations, desc="Expanding and filtering criteria configurations")
        ):
            can_be_matched = []
            for configuration in cve.vulnerable_criteria_configurations:
                configuration.expand_and_filter(matching_dict, relevant_cpe_uris)
                can_be_matched.append(not any(len(component) == 0 for component in configuration._expanded_components))
            if not any(can_be_matched):
                indices_to_delete.append(index)

        for index in sorted(indices_to_delete, reverse=True):
            del self._cves_with_vulnerable_configurations[index]

    def build_lookup_dict(
        self,
        cpe_match_feed: dict,
        limit_to_cpes: set[CPE] = set(),
    ):
        self._cpe_uri_to_cve_ids_lookup = {}
        cpe_uris_of_interest = {x.uri for x in limit_to_cpes} if limit_to_cpes else None
        self._get_cves_with_criteria_configurations()
        self._expand_criteria_configurations(cpe_match_feed, cpe_uris_of_interest)

        logger.info("Building lookup dictionaries.")
        cve: CVE
        for cve in tqdm(self, desc="Building-up lookup dictionaries for fast CVE matching"):
            vulnerable_cpe_uris: set[str] = set()
            for x in cve.vulnerable_criteria:
                if x.criteria_id not in cpe_match_feed["match_strings"]:
                    # This happens when there's no `matches` key in the original dict. In such case, the whole key got
                    # discarded. Statistically, approx. 13% of criteria match to no CPEs and are used solely as criteria.
                    continue
                matches = cpe_match_feed["match_strings"][x.criteria_id]["matches"]
                vulnerable_cpe_uris = vulnerable_cpe_uris.union(x["cpeName"] for x in matches)

            if (
                cpe_uris_of_interest
                and not cve.vulnerable_criteria_configurations
                and not any(x in cpe_uris_of_interest for x in vulnerable_cpe_uris)
            ):
                continue

            for cpe_uri in vulnerable_cpe_uris:
                if not cpe_uris_of_interest or cpe_uri in cpe_uris_of_interest:
                    self._cpe_uri_to_cve_ids_lookup.setdefault(cpe_uri, set()).add(cve.cve_id)

    def _get_cves_from_exactly_matched_cpes(self, cpe_uris: set[str]) -> set[str]:
        return set(
            itertools.chain.from_iterable([self._cpe_uri_to_cve_ids_lookup.get(cpe_uri, set()) for cpe_uri in cpe_uris])
        )

    def _get_cves_from_criteria_configurations(self, cpe_uris: set[str]) -> set[str]:
        return {
            cve.cve_id
            for cve in self._cves_with_vulnerable_configurations
            if any(configuration.matches(cpe_uris) for configuration in cve.vulnerable_criteria_configurations)
        }

    def get_cves_from_matched_cpe_uris(self, cpe_uris: set[str]) -> set[str]:
        """
        Method returns the set of CVEs which are matched to the set of CPE uris.
        """
        return {
            *self._get_cves_from_exactly_matched_cpes(cpe_uris),
            *self._get_cves_from_criteria_configurations(cpe_uris),
        }

    def to_pandas(self) -> pd.DataFrame:
        df = pd.DataFrame([x.pandas_tuple for x in self], columns=CVE.pandas_columns)
        df.cwe_ids = df.cwe_ids.map(lambda x: x if x else np.nan)
        return df.set_index("cve_id")

    def enhance_with_nvd_data(self, data: dict[str, Any]) -> CVEDataset:
        self.last_update_timestamp = datetime.fromisoformat(data["timestamp"])
        for vuln in data["vulnerabilities"]:
            # https://nvd.nist.gov/vuln/vulnerability-status#divNvdStatus
            if vuln["cve"]["vulnStatus"] in {"Analyzed", "Modified"}:
                cve = CVE.from_nist_dict(vuln["cve"])
                self[cve.cve_id] = cve
        return self
