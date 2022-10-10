import json
import logging
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple, Union

import sec_certs.utils.helpers as helpers
from sec_certs.config.configuration import config
from sec_certs.sample.protection_profile import ProtectionProfile

logger = logging.getLogger(__name__)


@dataclass
class ProtectionProfileDataset:
    pps: Dict[Tuple[str, Optional[str]], ProtectionProfile]

    def __iter__(self):
        yield from self.pps.values()

    def __getitem__(self, item: Tuple[str, Optional[str]]) -> ProtectionProfile:
        return self.pps.__getitem__(item)

    def __setitem__(self, key: Tuple[str, Optional[str]], value: ProtectionProfile):
        self.pps.__setitem__(key, value)

    def __contains__(self, key):
        return key in self.pps

    def __len__(self) -> int:
        return len(self.pps)

    @classmethod
    def from_json(cls, json_path: Union[str, Path]):
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
    def from_web(cls, store_dataset_path: Optional[Path] = None):

        logger.info(f"Downloading static PP dataset from: {config.pp_latest_snapshot}")
        if not store_dataset_path:
            tmp = tempfile.TemporaryDirectory()
            store_dataset_path = Path(tmp.name) / "pp_dataset.json"

        helpers.download_file(config.pp_latest_snapshot, store_dataset_path)
        obj = cls.from_json(store_dataset_path)

        if not store_dataset_path:
            tmp.cleanup()

        return obj
