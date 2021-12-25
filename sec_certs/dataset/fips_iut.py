from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Mapping, Union

from sec_certs.dataset.dataset import logger
from sec_certs.helpers import tqdm
from sec_certs.sample.fips_iut import IUTSnapshot
from sec_certs.serialization.json import ComplexSerializableType


@dataclass
class IUTDataset(ComplexSerializableType):
    snapshots: List[IUTSnapshot]

    def __iter__(self) -> Iterator[IUTSnapshot]:
        yield from self.snapshots

    def __getitem__(self, item: int) -> IUTSnapshot:
        return self.snapshots.__getitem__(item)

    def __len__(self) -> int:
        return len(self.snapshots)

    @classmethod
    def from_dumps(cls, dump_path: Union[str, Path]) -> "IUTDataset":
        directory = Path(dump_path)
        fnames = list(directory.glob("*"))
        snapshots = []
        for dump_path in tqdm(sorted(fnames), total=len(fnames)):
            try:
                snapshots.append(IUTSnapshot.from_dump(dump_path))
            except Exception as e:
                logger.error(e)
        return cls(snapshots)

    def to_dict(self) -> Dict[str, List[IUTSnapshot]]:
        return {"snapshots": list(self.snapshots)}

    @classmethod
    def from_dict(cls, dct: Mapping) -> "IUTDataset":
        return cls(dct["snapshots"])
