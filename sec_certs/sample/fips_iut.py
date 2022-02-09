from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Dict, Iterator, List, Mapping, Optional, Set, Union

import requests
from bs4 import BeautifulSoup, Tag

from sec_certs.helpers import to_utc
from sec_certs.serialization.json import ComplexSerializableType


@dataclass(frozen=True)
class IUTEntry(ComplexSerializableType):
    module_name: str
    vendor_name: str
    standard: str
    iut_date: date

    def to_dict(self) -> Dict[str, str]:
        return {**self.__dict__, "iut_date": self.iut_date.isoformat()}

    @classmethod
    def from_dict(cls, dct: Mapping) -> "IUTEntry":
        return cls(
            dct["module_name"],
            dct["vendor_name"],
            dct["standard"],
            date.fromisoformat(dct["iut_date"]),
        )


@dataclass
class IUTSnapshot(ComplexSerializableType):
    entries: Set[IUTEntry]
    timestamp: datetime
    last_updated: date
    displayed: Optional[int]
    not_displayed: Optional[int]
    total: Optional[int]

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[IUTEntry]:
        yield from self.entries

    def to_dict(self) -> Dict[str, Union[Optional[int], List[IUTEntry], str]]:
        return {
            "entries": list(self.entries),
            "timestamp": self.timestamp.isoformat(),
            "last_updated": self.last_updated.isoformat(),
            "displayed": self.displayed,
            "not_displayed": self.not_displayed,
            "total": self.total,
        }

    @classmethod
    def from_dict(cls, dct: Mapping) -> "IUTSnapshot":
        return cls(
            set(dct["entries"]),
            datetime.fromisoformat(dct["timestamp"]),
            date.fromisoformat(dct["last_updated"]),
            dct["displayed"],
            dct["not_displayed"],
            dct["total"],
        )

    @classmethod
    def from_page(cls, content: bytes, snapshot_date: datetime) -> "IUTSnapshot":
        if not content:
            raise ValueError("Empty content in IUT.")
        soup = BeautifulSoup(content, "html.parser")
        tables = soup.find_all("table")
        if len(tables) != 1:
            raise ValueError("Not only a single table in IUT.")

        last_updated_elem = next(
            filter(
                lambda e: isinstance(e, Tag) and e.name == "p",
                soup.find(id="content").next_siblings,
            )
        )
        last_updated_text = str(last_updated_elem.string).strip()
        last_updated = datetime.strptime(last_updated_text, "Last Updated: %m/%d/%Y").date()
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

        # Parse footer
        footer = soup.find(id="IUTFooter")
        displayed: Optional[int]
        not_displayed: Optional[int]
        total: Optional[int]

        if footer:
            footer_lines = footer.find_all("tr")
            displayed = int(footer_lines[0].find_all("td")[1].text)
            not_displayed = int(footer_lines[1].find_all("td")[1].text)
            total = int(footer_lines[2].find_all("td")[1].text)
        else:
            displayed, not_displayed, total = (None, None, None)

        return cls(
            entries=entries,
            timestamp=snapshot_date,
            last_updated=last_updated,
            displayed=displayed,
            not_displayed=not_displayed,
            total=total,
        )

    @classmethod
    def from_dump(cls, dump_path: Union[str, Path], snapshot_date: Optional[datetime] = None) -> "IUTSnapshot":
        dump_path = Path(dump_path)
        if snapshot_date is None:
            try:
                snapshot_date = to_utc(datetime.fromisoformat(dump_path.name[len("fips_iut_") : -len(".html")]))
            except Exception:
                raise ValueError("snapshot_date not given and could not be inferred from filename.")
        with dump_path.open("rb") as f:
            content = f.read()
        return cls.from_page(content, snapshot_date)

    @classmethod
    def from_web(cls) -> "IUTSnapshot":
        iut_url = "https://csrc.nist.gov/Projects/cryptographic-module-validation-program/modules-in-process/IUT-List"
        iut_resp = requests.get(iut_url)
        if iut_resp.status_code != 200:
            raise ValueError("Getting MIP snapshot failed")

        snapshot_date = to_utc(datetime.now())
        return cls.from_page(iut_resp.content, snapshot_date)
