from dataclasses import dataclass
from typing import Dict, Tuple, Union, Optional, ClassVar
from pathlib import Path
import json
import logging
import tempfile

import sec_certs.helpers as helpers
from sec_certs.sample.protection_profile import ProtectionProfile

logger = logging.getLogger(__name__)


@dataclass
class ProtectionProfileDataset:
    static_dataset_url: ClassVar[str] = 'https://ajanovsky.cz/pp_data_complete_processed.json'

    pps: Dict[Tuple[str, str], ProtectionProfile]

    def __iter__(self):
        yield from self.pps.values()

    def __getitem__(self, item: Tuple[str, str]) -> ProtectionProfile:
        return self.pps.__getitem__(item)

    def __setitem__(self, key: Tuple[str, str], value: ProtectionProfile):
        self.pps.__setitem__(key, value)

    def __contains__(self, key):
        return key in self.pps

    def __len__(self) -> int:
        return len(self.pps)

    @classmethod
    def from_json(cls, json_path: Union[str, Path]):
        with Path(json_path).open('r') as handle:
            data = json.load(handle)
        pps = [ProtectionProfile.from_old_api_dict(x) for x in data.values()]

        dct = {}
        for item in pps:
            if (item.pp_name, item.pp_link) in dct:
                logger.warning(f'Duplicate entry in PP dataset: {(item.pp_name, item.pp_link)}')
            dct[(item.pp_name, item.pp_link)] = item

        return cls(dct)

    @classmethod
    def from_web(cls, store_dataset_path: Optional[Union[str, Path]]):
        logger.info(f'Downloading static PP dataset from: {cls.static_dataset_url}')
        if not store_dataset_path:
            tmp = tempfile.TemporaryDirectory()
            store_dataset_path = Path(tmp.name)

        helpers.download_file(cls.static_dataset_url, store_dataset_path)
        obj = cls.from_json(store_dataset_path)

        if not store_dataset_path:
            tmp.cleanup()

        return obj
