from dataclasses import dataclass
from pathlib import Path
from typing import List, Mapping, Union

from tqdm import tqdm

from sec_certs.sample.fips_iut import IUTSnapshot
from sec_certs.serialization.json import ComplexSerializableType


@dataclass
class IUTDataset(ComplexSerializableType):
    snapshots: List[IUTSnapshot]

    def __iter__(self):
        yield from self.snapshots

    def __getitem__(self, item: int) -> IUTSnapshot:
        return self.snapshots.__getitem__(item)

    def __len__(self) -> int:
        return len(self.snapshots)

    @classmethod
    def from_dumps(cls, dump_path: Union[str, Path]) -> "IUTDataset":
        directory = Path(dump_path)
        fnames = list(directory.glob("*"))
        snapshots = [IUTSnapshot.from_dump(dump_path) for dump_path in tqdm(sorted(fnames), total=len(fnames))]
        return cls(snapshots)

    def to_dict(self):
        return {"snapshots": list(self.snapshots)}

    @classmethod
    def from_dict(cls, dct: Mapping) -> "IUTDataset":
        return cls(dct["snapshots"])
