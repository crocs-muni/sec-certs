import json
import logging

from dataclasses import dataclass
from enum import Enum
from typing import List, Set, Mapping, Union
from datetime import datetime, date
from pathlib import Path

from tqdm import tqdm
from bs4 import BeautifulSoup, Tag
from sec_certs.serialization import ComplexSerializableType, CustomJSONEncoder, CustomJSONDecoder


logger = logging.getLogger(__name__)


class MIPStatus(Enum):
    IN_REVIEW = "In Review"
    REVIEW_PENDING = "Review Pending"
    COORDINATION = "Coordination"
    FINALIZATION = "Finalization"


@dataclass(frozen=True)
class MIPEntry(ComplexSerializableType):
    module_name: str
    vendor_name: str
    standard: str
    status: MIPStatus

    def to_dict(self):
        return {**self.__dict__, "status": self.status.value}

    @classmethod
    def from_dict(cls, dct: Mapping) -> "MIPEntry":
        return cls(
            dct["module_name"],
            dct["vendor_name"],
            dct["standard"],
            MIPStatus(dct["status"]),
        )


@dataclass
class MIPSnapshot(ComplexSerializableType):
    entries: Set[MIPEntry]
    timestamp: datetime
    last_updated: date

    def to_dict(self):
        return {
            "entries": list(self.entries),
            "timestamp": self.timestamp.isoformat(),
            "last_updated": self.last_updated.isoformat(),
        }

    @classmethod
    def from_dict(cls, dct: Mapping) -> "MIPSnapshot":
        return cls(
            set(dct["entries"]),
            datetime.fromisoformat(dct["timestamp"]),
            date.fromisoformat(dct["last_updated"]),
        )


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
    def from_dump(cls, dump_path: Union[str, Path]) -> "MIPDataset":
        directory = Path(dump_path)
        snapshots = []
        fnames = list(directory.glob("*"))
        for fname in tqdm(sorted(fnames), total=len(fnames)):
            snapshot_date = to_utc(
                datetime.fromisoformat(fname.name[len("fips_mip_") : -len(".html")])
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
            if snapshot_date <= datetime(2020, 10, 28):
                # NIST had a different format of the MIP table before this date, handle it.
                entries = set()
                for tr in lines:
                    tds = tr.find_all("td")
                    status = None
                    if "mip-highlight" in tds[-1]["class"]:
                        status = MIPStatus.FINALIZATION
                    elif "mip-highlight" in tds[-2]["class"]:
                        status = MIPStatus.COORDINATION
                    elif "mip-highlight" in tds[-3]["class"]:
                        status = MIPStatus.REVIEW_PENDING
                    elif "mip-highlight" in tds[-4]["class"]:
                        status = MIPStatus.IN_REVIEW
                    entries.add(
                        MIPEntry(
                            str(tds[0].string),
                            str(tds[1].string),
                            str(tds[2].string),
                            status,
                        )
                    )
            else:
                entries = {
                    MIPEntry(
                        str(line[0].string),
                        str(line[1].string),
                        str(line[2].string),
                        MIPStatus(str(line[3].string)),
                    )
                    for line in map(lambda tr: tr.find_all("td"), lines)
                }
            snapshots.append(MIPSnapshot(entries, snapshot_date, last_updated))
        return cls(snapshots)


    def to_dict(self):
        return {
            "snapshots": list(self.snapshots)
        }

    @classmethod
    def from_dict(cls, dct: Mapping) -> "MIPDataset":
        return cls(
            dct["snapshots"]
        )

    def to_json(self, json_path: Union[str, Path]):
        with open(json_path, 'w') as handle:
            json.dump(self, handle, indent=4, cls=CustomJSONEncoder)

    @classmethod
    def from_json(cls, json_path: Union[str, Path]):
        with Path(json_path).open('r') as handle:
            return json.load(handle, cls=CustomJSONDecoder)
