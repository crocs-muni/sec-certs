from __future__ import annotations

import json
import logging
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from sec_certs import constants
from sec_certs.configuration import config
from sec_certs.sample.protection_profile import ProtectionProfile
from sec_certs.serialization.json import get_class_fullname
from sec_certs.utils import helpers

logger = logging.getLogger(__name__)


@dataclass
class ProtectionProfileDataset:
    pps: dict[tuple[str, str | None], ProtectionProfile]
    _json_path: Path

    def __init__(
        self,
        pps: dict[tuple[str, str | None], ProtectionProfile],
        json_path: str | Path = constants.DUMMY_NONEXISTING_PATH,
    ) -> None:
        self.pps = pps
        self.json_path = Path(json_path)

    @property
    def json_path(self):
        return self._json_path

    @json_path.setter
    def json_path(self, new_path: str | Path):
        new_path = Path(new_path)
        if new_path.is_dir():
            raise ValueError(f"Json path of {get_class_fullname(self)} cannot be a directory.")

        self._json_path = new_path

    def move_dataset(self, new_json_path: str | Path) -> None:
        logger.info(f"Moving {get_class_fullname(self)} dataset to {new_json_path}")
        new_json_path = Path(new_json_path)
        new_json_path.parent.mkdir(parents=True, exist_ok=True)

        if not self.json_path.exists():
            raise ValueError("Cannot move the PPDataset if the json path does not exist.")

        shutil.move(str(self.json_path), str(new_json_path))
        self.json_path = new_json_path

    def __iter__(self):
        yield from self.pps.values()

    def __getitem__(self, item: tuple[str, str | None]) -> ProtectionProfile:
        return self.pps.__getitem__(item)

    def __setitem__(self, key: tuple[str, str | None], value: ProtectionProfile):
        self.pps.__setitem__(key, value)

    def __contains__(self, key):
        return key in self.pps

    def __len__(self) -> int:
        return len(self.pps)

    @classmethod
    def from_json(cls, json_path: str | Path):
        with Path(json_path).open("r") as handle:
            data = json.load(handle)
        pps = [ProtectionProfile.from_old_api_dict(x) for x in data.values()]

        dct = {}
        for item in pps:
            if (item.pp_name, item.pp_link) in dct:
                logger.warning(f"Duplicate entry in PP dataset: {(item.pp_name, item.pp_link)}")
            dct[(item.pp_name, item.pp_link)] = item

        return cls(dct)

    @classmethod
    def from_web(cls, store_dataset_path: Path | None = None):
        logger.info(f"Downloading static PP dataset from: {config.pp_latest_snapshot}")
        if not store_dataset_path:
            tmp = tempfile.TemporaryDirectory()
            store_dataset_path = Path(tmp.name) / "pp_dataset.json"

        helpers.download_file(config.pp_latest_snapshot, store_dataset_path)
        obj = cls.from_json(store_dataset_path)

        if not store_dataset_path:
            tmp.cleanup()

        return obj
