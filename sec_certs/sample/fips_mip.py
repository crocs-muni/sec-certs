import logging
from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Dict, Iterator, List, Mapping, Optional, Set, Union

import requests
from bs4 import BeautifulSoup, Tag

from sec_certs.constants import FIPS_MIP_STATUS_RE
from sec_certs.helpers import to_utc
from sec_certs.serialization.json import ComplexSerializableType

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
    status: Optional[MIPStatus]
    status_since: Optional[date]

    def to_dict(self) -> Dict[str, Union[str, Optional[MIPStatus], Optional[date]]]:
        return {
            **self.__dict__,
            "status": self.status.value if self.status else None,
            "status_since": self.status_since.isoformat() if self.status_since else None,
        }

    @classmethod
    def from_dict(cls, dct: Mapping) -> "MIPEntry":
        return cls(
            dct["module_name"],
            dct["vendor_name"],
            dct["standard"],
            MIPStatus(dct["status"]) if dct["status"] else None,
            date.fromisoformat(dct["status_since"]) if dct.get("status_since") else None,
        )


@dataclass
class MIPSnapshot(ComplexSerializableType):
    entries: Set[MIPEntry]
    timestamp: datetime
    last_updated: date
    displayed: int
    not_displayed: int
    total: int

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[MIPEntry]:
        yield from self.entries

    def to_dict(self) -> Dict[str, Union[int, str, List[MIPEntry]]]:
        return {
            "entries": list(self.entries),
            "timestamp": self.timestamp.isoformat(),
            "last_updated": self.last_updated.isoformat(),
            "displayed": self.displayed,
            "not_displayed": self.not_displayed,
            "total": self.total,
        }

    @classmethod
    def from_dict(cls, dct: Mapping) -> "MIPSnapshot":
        return cls(
            set(dct["entries"]),
            datetime.fromisoformat(dct["timestamp"]),
            date.fromisoformat(dct["last_updated"]),
            dct["displayed"],
            dct["not_displayed"],
            dct["total"],
        )

    @classmethod
    def _extract_entries_1(cls, lines):
        """Works until 2020.10.28 (including)."""
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
            entries.add(MIPEntry(str(tds[0].string), str(tds[1].string), str(tds[2].string), status, None))
        return entries

    @classmethod
    def _extract_entries_2(cls, lines):
        """Works until 2021.04.20 (including)."""
        return {
            MIPEntry(
                str(line[0].string), str(line[1].string), str(line[2].string), MIPStatus(str(line[3].string)), None
            )
            for line in map(lambda tr: tr.find_all("td"), lines)
        }

    @classmethod
    def _extract_entries_3(cls, lines):
        """Works until 2022.03.23 (including)."""
        return {
            MIPEntry(
                str(line[0].string),
                str(" ".join(line[1].find_all(text=True, recursive=False)).strip()),
                str(line[2].string),
                MIPStatus(str(line[3].string)),
                None,
            )
            for line in map(lambda tr: tr.find_all("td"), lines)
        }

    @classmethod
    def _extract_entries_4(cls, lines):
        """Works now."""
        entries = set()
        for line in map(lambda tr: tr.find_all("td"), lines):
            module_name = str(line[0].string)
            vendor_name = str(" ".join(line[1].find_all(text=True, recursive=False)).strip())
            standard = str(line[2].string)
            status_line = FIPS_MIP_STATUS_RE.match(str(line[3].string))
            if status_line is None:
                raise ValueError("Cannot parse MIP status line.")
            status = MIPStatus(status_line.group("status"))
            since = datetime.strptime(status_line.group("since"), "%m/%d/%Y").date()
            entries.add(MIPEntry(module_name, vendor_name, standard, status, since))
        return entries

    @classmethod
    def _extract_entries(cls, lines, snapshot_date):
        if snapshot_date <= datetime(2020, 10, 28):
            entries = cls._extract_entries_1(lines)
        elif snapshot_date <= datetime(2021, 4, 20):
            entries = cls._extract_entries_2(lines)
        elif snapshot_date <= datetime(2022, 3, 23):
            entries = cls._extract_entries_3(lines)
        else:
            entries = cls._extract_entries_4(lines)
        return entries

    @classmethod
    def from_page(cls, content: bytes, snapshot_date: datetime) -> "MIPSnapshot":
        if not content:
            raise ValueError("Empty content in MIP.")
        soup = BeautifulSoup(content, "html.parser")
        tables = soup.find_all("table")
        if len(tables) != 1:
            raise ValueError("Not only a single table in MIP data.")

        # Parse Last Updated
        last_updated_elem = next(
            filter(
                lambda e: isinstance(e, Tag) and e.name == "p",
                soup.find(id="content").next_siblings,
            )
        )
        last_updated_text = str(last_updated_elem.string).strip()
        last_updated = datetime.strptime(last_updated_text, "Last Updated: %m/%d/%Y").date()

        # Parse entries
        table = tables[0].find("tbody")
        lines = table.find_all("tr")
        entries = cls._extract_entries(lines, snapshot_date)

        # Parse footer
        footer = soup.find(id="MIPFooter")
        footer_lines = footer.find_all("tr")
        displayed = int(footer_lines[0].find_all("td")[1].text)
        not_displayed = int(footer_lines[1].find_all("td")[1].text)
        total = int(footer_lines[2].find_all("td")[1].text)

        return cls(
            entries=entries,
            timestamp=snapshot_date,
            last_updated=last_updated,
            displayed=displayed,
            not_displayed=not_displayed,
            total=total,
        )

    @classmethod
    def from_dump(cls, dump_path: Union[str, Path], snapshot_date: Optional[datetime] = None) -> "MIPSnapshot":
        dump_path = Path(dump_path)
        if snapshot_date is None:
            try:
                snapshot_date = to_utc(datetime.fromisoformat(dump_path.name[len("fips_mip_") : -len(".html")]))
            except Exception:
                raise ValueError("snapshot_date not given and could not be inferred from filename.")
        with dump_path.open("rb") as f:
            content = f.read()
        return cls.from_page(content, snapshot_date)

    @classmethod
    def from_web(cls) -> "MIPSnapshot":
        mip_url = "https://csrc.nist.gov/Projects/cryptographic-module-validation-program/modules-in-process/Modules-In-Process-List"
        mip_resp = requests.get(mip_url)
        if mip_resp.status_code != 200:
            raise ValueError("Getting MIP snapshot failed")

        snapshot_date = to_utc(datetime.now())
        return cls.from_page(mip_resp.content, snapshot_date)
