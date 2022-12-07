from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Iterator, Mapping

import requests

from sec_certs import constants
from sec_certs.config.configuration import config
from sec_certs.dataset.dataset import logger
from sec_certs.dataset.json_path_dataset import JSONPathDataset
from sec_certs.sample.fips_mip import MIPSnapshot
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils.tqdm import tqdm


@dataclass
class MIPDataset(JSONPathDataset, ComplexSerializableType):
    snapshots: list[MIPSnapshot]
    _json_path: Path

    def __init__(self, snapshots: list[MIPSnapshot], json_path: str | Path = constants.DUMMY_NONEXISTING_PATH):
        self.snapshots = snapshots
        self.json_path = Path(json_path)

    def __iter__(self) -> Iterator[MIPSnapshot]:
        yield from self.snapshots

    def __getitem__(self, item: int) -> MIPSnapshot:
        return self.snapshots.__getitem__(item)

    def __len__(self) -> int:
        return len(self.snapshots)

    @classmethod
    def from_dumps(cls, dump_path: str | Path) -> MIPDataset:
        directory = Path(dump_path)
        fnames = list(directory.glob("*"))
        snapshots = []
        for dump_path in tqdm(sorted(fnames), total=len(fnames)):
            try:
                snapshots.append(MIPSnapshot.from_dump(dump_path))
            except Exception as e:
                logger.error(e)
        return cls(snapshots)

    def to_dict(self) -> dict[str, list[MIPSnapshot]]:
        return {"snapshots": list(self.snapshots)}

    @classmethod
    def from_dict(cls, dct: Mapping) -> MIPDataset:
        return cls(dct["snapshots"])

    @classmethod
    def from_web_latest(cls) -> MIPDataset:
        """
        Get the MIPDataset from seccerts.org
        """
        mip_resp = requests.get(config.fips_mip_dataset)
        if mip_resp.status_code != 200:
            raise ValueError(f"Getting MIP dataset failed: {mip_resp.status_code}")
        with NamedTemporaryFile() as tmpfile:
            tmpfile.write(mip_resp.content)
            return cls.from_json(tmpfile.name)
