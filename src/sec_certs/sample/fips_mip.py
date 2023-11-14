from __future__ import annotations

import logging
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum
from functools import total_ordering
from pathlib import Path
from tempfile import NamedTemporaryFile

import requests
from bs4 import BeautifulSoup, Tag

from sec_certs import constants
from sec_certs.configuration import config
from sec_certs.constants import FIPS_MIP_STATUS_RE
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils.helpers import to_utc

logger = logging.getLogger(__name__)


@total_ordering
class MIPStatus(Enum):
    IN_REVIEW = "In Review"
    REVIEW_PENDING = "Review Pending"
    COORDINATION = "Coordination"
    FINALIZATION = "Finalization"

    def __lt__(self, other):
        if self.__class__ == other.__class__:
            mb = list(MIPStatus.__members__.keys())
            return mb.index(self.name) < mb.index(other.name)
        raise NotImplementedError


@dataclass(frozen=True, order=True)
class MIPEntry(ComplexSerializableType):
    module_name: str
    vendor_name: str
    standard: str
    status: MIPStatus
    status_since: date | None

    def to_dict(self) -> dict[str, str | MIPStatus | date | None]:
        return {
            **self.__dict__,
            "status": self.status.value,
            "status_since": self.status_since.isoformat() if self.status_since else None,
        }

    @classmethod
    def from_dict(cls, dct: Mapping) -> MIPEntry:
        return cls(
            dct["module_name"],
            dct["vendor_name"],
            dct["standard"],
            MIPStatus(dct["status"]),
            date.fromisoformat(dct["status_since"]) if dct.get("status_since") else None,
        )


@dataclass
class MIPFlow(ComplexSerializableType):
    module_name: str
    vendor_name: str
    standard: str
    state_changes: list[tuple[date, MIPStatus]]

    def to_dict(self) -> dict[str, str | list]:
        return {**self.__dict__, "state_changes": [(dt.isoformat(), status.value) for dt, status in self.state_changes]}

    @classmethod
    def from_dict(cls, dct: Mapping) -> MIPFlow:
        return cls(
            dct["module_name"],
            dct["vendor_name"],
            dct["standard"],
            [(date.fromisoformat(dt), MIPStatus(status)) for dt, status in dct["state_changes"]],
        )


@dataclass
class MIPSnapshot(ComplexSerializableType):
    entries: set[MIPEntry]
    timestamp: datetime
    last_updated: date
    displayed: int
    not_displayed: int
    total: int

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[MIPEntry]:
        yield from self.entries

    def to_dict(self) -> dict[str, int | str | list[MIPEntry]]:
        return {
            "entries": list(self.entries),
            "timestamp": self.timestamp.isoformat(),
            "last_updated": self.last_updated.isoformat(),
            "displayed": self.displayed,
            "not_displayed": self.not_displayed,
            "total": self.total,
        }

    @classmethod
    def from_dict(cls, dct: Mapping) -> MIPSnapshot:
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
            if "mip-highlight" in tds[-1]["class"]:
                status = MIPStatus.FINALIZATION
            elif "mip-highlight" in tds[-2]["class"]:
                status = MIPStatus.COORDINATION
            elif "mip-highlight" in tds[-3]["class"]:
                status = MIPStatus.REVIEW_PENDING
            elif "mip-highlight" in tds[-4]["class"]:
                status = MIPStatus.IN_REVIEW
            else:
                raise ValueError("Cannot parse MIP status line.")
            entries.add(MIPEntry(str(tds[0].string), str(tds[1].string), str(tds[2].string), status, None))
        return entries

    @classmethod
    def _extract_entries_2(cls, lines):
        """Works until 2021.04.20 (including)."""
        return {
            MIPEntry(
                str(line[0].string), str(line[1].string), str(line[2].string), MIPStatus(str(line[3].string)), None
            )
            for line in (tr.find_all("td") for tr in lines)
        }

    @classmethod
    def _extract_entries_3(cls, lines):
        """Works until 2022.03.23 (including)."""
        return {
            MIPEntry(
                str(line[0].string),
                str(" ".join(line[1].find_all(string=True, recursive=False)).strip()),
                str(line[2].string),
                MIPStatus(str(line[3].string)),
                None,
            )
            for line in (tr.find_all("td") for tr in lines)
        }

    @classmethod
    def _extract_entries_4(cls, lines):
        """Works now."""
        entries = set()
        for line in (tr.find_all("td") for tr in lines):
            module_name = str(line[0].string)
            vendor_name = str(" ".join(line[1].find_all(string=True, recursive=False)).strip())
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
            return cls._extract_entries_1(lines)
        if snapshot_date <= datetime(2021, 4, 20):
            return cls._extract_entries_2(lines)
        if snapshot_date <= datetime(2022, 3, 23):
            return cls._extract_entries_3(lines)
        return cls._extract_entries_4(lines)

    @classmethod
    def from_page(cls, content: bytes, snapshot_date: datetime) -> MIPSnapshot:
        """
        Get a MIP snapshot from a HTML dump of the FIPS website.
        """
        if not content:
            raise ValueError("Empty content in MIP.")
        soup = BeautifulSoup(content, "html5lib")
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
    def from_dump(cls, dump_path: str | Path, snapshot_date: datetime | None = None) -> MIPSnapshot:
        """
        Get a MIP snapshot from a HTML file dump of the FIPS website.
        """
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
    def from_web(cls) -> MIPSnapshot:
        """
        Get a MIP snapshot from the FIPS website right now.
        """
        mip_resp = requests.get(constants.FIPS_MIP_URL)
        if mip_resp.status_code != 200:
            raise ValueError(f"Getting MIP snapshot failed: {mip_resp.status_code}")

        snapshot_date = to_utc(datetime.now())
        return cls.from_page(mip_resp.content, snapshot_date)

    @classmethod
    def from_web_latest(cls) -> MIPSnapshot:
        """
        Get a MIP snapshot from seccerts.org.
        """
        mip_resp = requests.get(config.fips_mip_latest_snapshot)
        if mip_resp.status_code != 200:
            raise ValueError(f"Getting MIP snapshot failed: {mip_resp.status_code}")
        with NamedTemporaryFile() as tmpfile:
            tmpfile.write(mip_resp.content)
            return cls.from_json(tmpfile.name)
