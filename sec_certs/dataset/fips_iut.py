import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Union, Mapping

from bs4 import BeautifulSoup, Tag
from tqdm import tqdm

from sec_certs.helpers import to_utc
from sec_certs.dataset.dataset import logger
from sec_certs.sample.fips_iut import IUTEntry, IUTSnapshot
from sec_certs.serialization.json import ComplexSerializableType, CustomJSONEncoder, CustomJSONDecoder


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
    def from_dump(cls, dump_path: Union[str, Path]) -> "IUTDataset":
        directory = Path(dump_path)
        snapshots = []
        fnames = list(directory.glob("*"))
        for fname in tqdm(sorted(fnames), total=len(fnames)):
            snapshot_date = to_utc(
                datetime.fromisoformat(fname.name[len("fips_iut_") : -len(".html")])
            )
            with open(fname) as f:
                soup = BeautifulSoup(f, "html.parser")
            tables = soup.find_all("table")
            if len(tables) != 1:
                logger.error(f"*** Not only a single table in {fname}.")
                continue
            last_updated_elem = next(
                filter(
                    lambda e: isinstance(e, Tag) and e.name == "p",
                    soup.find(id="content").next_siblings,
                )
            )
            last_updated_text = str(last_updated_elem.string).strip()
            last_updated = datetime.strptime(
                last_updated_text, "Last Updated: %m/%d/%Y"
            ).date()
            table = tables[0].find("tbody")
            lines = table.find_all("tr")
            entries = {
                IUTEntry(
                    str(line[0].string),
                    str(line[1].string),
                    str(line[2].string),
                    datetime.strptime(str(line[3].string), "%m/%d/%Y").date(),
                )
                for line in map(lambda tr: tr.find_all("td"), lines)
            }
            snapshots.append(IUTSnapshot(entries, snapshot_date, last_updated))
        return cls(snapshots)

    def to_dict(self):
        return {
            "snapshots": list(self.snapshots)
        }

    @classmethod
    def from_dict(cls, dct: Mapping) -> "IUTDataset":
        return cls(
            dct["snapshots"]
        )

    def to_json(self, json_path: Union[str, Path]):
        with open(json_path, 'w') as handle:
            json.dump(self, handle, indent=4, cls=CustomJSONEncoder)

    @classmethod
    def from_json(cls, json_path: Union[str, Path]) -> "IUTDataset":
        with Path(json_path).open('r') as handle:
            return json.load(handle, cls=CustomJSONDecoder)
