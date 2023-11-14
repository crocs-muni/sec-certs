from __future__ import annotations

import logging
import tempfile
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

import sec_certs.configuration as config_module
from sec_certs import constants
from sec_certs.dataset.json_path_dataset import JSONPathDataset
from sec_certs.sample.cpe import CPE
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils import helpers

logger = logging.getLogger(__name__)


class CPEDataset(JSONPathDataset, ComplexSerializableType):
    """
    Dataset of CPE records. Includes look-up dictionaries for fast search.
    """

    def __init__(
        self,
        cpes: dict[str, CPE] = {},
        json_path: str | Path = constants.DUMMY_NONEXISTING_PATH,
        last_update_timestamp: datetime = datetime.fromtimestamp(0),
    ):
        self.cpes = cpes
        self.json_path = Path(json_path)
        self.last_update_timestamp = last_update_timestamp

    def __iter__(self) -> Iterator[CPE]:
        yield from self.cpes.values()

    def __getitem__(self, item: str) -> CPE:
        return self.cpes.__getitem__(item.lower())

    def __setitem__(self, key: str, value: CPE) -> None:
        self.cpes.__setitem__(key.lower(), value)

    def __delitem__(self, key: str) -> None:
        del self.cpes[key]

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
        return ["last_update_timestamp", "cpes"]

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
            if (
                not helpers.download_file(
                    config_module.config.cpe_latest_snapshot,
                    dset_path,
                    progress_bar_desc="Downloading CPEDataset from web",
                )
                == constants.RESPONSE_OK
            ):
                raise RuntimeError(f"Could not download CPEDataset from {config_module.config.cpe_latest_snapshot}.")
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

    def _find_uris_for_ids(self, ids: set[str]) -> set[str]:
        return {x.uri for x in self if x.uri in ids}

    def to_pandas(self) -> pd.DataFrame:
        """
        Turns the dataset into pandas DataFrame. Each CPE record forms a row.

        :return pd.DataFrame: the resulting DataFrame
        """
        return pd.DataFrame([x.pandas_tuple for x in self], columns=CPE.pandas_columns).set_index("uri")

    def get_title_to_cpes_dict(self) -> dict[str, set[CPE]]:
        title_to_cpes_dict: dict[str, set[CPE]] = {}
        for cpe in self:
            if cpe.title:
                title_to_cpes_dict.setdefault(cpe.title, set()).add(cpe)
        return title_to_cpes_dict
