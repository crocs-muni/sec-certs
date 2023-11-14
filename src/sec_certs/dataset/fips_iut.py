from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile

import requests

from sec_certs import constants
from sec_certs.configuration import config
from sec_certs.dataset.dataset import logger
from sec_certs.dataset.json_path_dataset import JSONPathDataset
from sec_certs.sample.fips_iut import IUTSnapshot
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils.tqdm import tqdm


@dataclass
class IUTDataset(JSONPathDataset, ComplexSerializableType):
    snapshots: list[IUTSnapshot]
    _json_path: Path

    def __init__(self, snapshots: list[IUTSnapshot], json_path: str | Path = constants.DUMMY_NONEXISTING_PATH):
        self.snapshots = snapshots
        self.json_path = Path(json_path)

    def __iter__(self) -> Iterator[IUTSnapshot]:
        yield from self.snapshots

    def __getitem__(self, item: int) -> IUTSnapshot:
        return self.snapshots.__getitem__(item)

    def __len__(self) -> int:
        return len(self.snapshots)

    @classmethod
    def from_dumps(cls, dump_path: str | Path) -> IUTDataset:
        directory = Path(dump_path)
        fnames = list(directory.glob("*"))
        snapshots = []
        for dump_path in tqdm(sorted(fnames), total=len(fnames)):
            try:
                snapshots.append(IUTSnapshot.from_dump(dump_path))
            except Exception as e:
                logger.error(e)
        return cls(snapshots)

    def to_dict(self) -> dict[str, list[IUTSnapshot]]:
        return {"snapshots": list(self.snapshots)}

    @classmethod
    def from_dict(cls, dct: Mapping) -> IUTDataset:
        return cls(dct["snapshots"])

    @classmethod
    def from_web_latest(cls) -> IUTDataset:
        """
        Get the IUTDataset from seccerts.org
        """
        iut_resp = requests.get(config.fips_iut_dataset)
        if iut_resp.status_code != 200:
            raise ValueError(f"Getting IUT dataset failed: {iut_resp.status_code}")
        with NamedTemporaryFile() as tmpfile:
            tmpfile.write(iut_resp.content)
            return cls.from_json(tmpfile.name)
