from dataclasses import dataclass
from pathlib import Path
from typing import List, Mapping, Union

from tqdm import tqdm

from sec_certs.sample.fips_mip import MIPSnapshot
from sec_certs.serialization.json import ComplexSerializableType


@dataclass
class MIPDataset(ComplexSerializableType):
    snapshots: List[MIPSnapshot]

    def __iter__(self):
        yield from self.snapshots

    def __getitem__(self, item: int) -> MIPSnapshot:
        return self.snapshots.__getitem__(item)

    def __len__(self) -> int:
        return len(self.snapshots)

    @classmethod
    def from_dumps(cls, dump_path: Union[str, Path]) -> "MIPDataset":
        directory = Path(dump_path)
        fnames = list(directory.glob("*"))
        snapshots = [MIPSnapshot.from_dump(dump_path) for dump_path in tqdm(sorted(fnames), total=len(fnames))]
        return cls(snapshots)

    def to_dict(self):
        return {"snapshots": list(self.snapshots)}

    @classmethod
    def from_dict(cls, dct: Mapping) -> "MIPDataset":
        return cls(dct["snapshots"])
