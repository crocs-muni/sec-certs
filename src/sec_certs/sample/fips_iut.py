from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile

import requests
from bs4 import BeautifulSoup, Tag

from sec_certs import constants
from sec_certs.configuration import config
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils.helpers import to_utc


@dataclass(frozen=True)
class IUTEntry(ComplexSerializableType):
    module_name: str
    vendor_name: str
    standard: str
    iut_date: date

    def to_dict(self) -> dict[str, str]:
        return {**self.__dict__, "iut_date": self.iut_date.isoformat()}

    @classmethod
    def from_dict(cls, dct: Mapping) -> IUTEntry:
        return cls(
            dct["module_name"],
            dct["vendor_name"],
            dct["standard"],
            date.fromisoformat(dct["iut_date"]),
        )


@dataclass
class IUTSnapshot(ComplexSerializableType):
    entries: set[IUTEntry]
    timestamp: datetime
    last_updated: date
    displayed: int | None
    not_displayed: int | None
    total: int | None

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[IUTEntry]:
        yield from self.entries

    def to_dict(self) -> dict[str, int | None | list[IUTEntry] | str]:
        return {
            "entries": list(self.entries),
            "timestamp": self.timestamp.isoformat(),
            "last_updated": self.last_updated.isoformat(),
            "displayed": self.displayed,
            "not_displayed": self.not_displayed,
            "total": self.total,
        }

    @classmethod
    def from_dict(cls, dct: Mapping) -> IUTSnapshot:
        return cls(
            set(dct["entries"]),
            datetime.fromisoformat(dct["timestamp"]),
            date.fromisoformat(dct["last_updated"]),
            dct["displayed"],
            dct["not_displayed"],
            dct["total"],
        )

    @classmethod
    def from_page(cls, content: bytes, snapshot_date: datetime) -> IUTSnapshot:
        """
        Get an IUT snapshot from a HTML dump of the FIPS website.
        """
        if not content:
            raise ValueError("Empty content in IUT.")
        soup = BeautifulSoup(content, "html5lib")
        tables = soup.find_all("table")
        if len(tables) != 1:
            raise ValueError("Not only a single table in IUT.")

        last_updated_elem = next(
            filter(
                lambda e: isinstance(e, Tag) and e.name == "p" and "Last Updated" in str(e.string),
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
            for line in (tr.find_all("td") for tr in lines)
        }

        # Parse footer
        footer = soup.find(id="IUTFooter")
        displayed: int | None
        not_displayed: int | None
        total: int | None

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
    def from_dump(cls, dump_path: str | Path, snapshot_date: datetime | None = None) -> IUTSnapshot:
        """
        Get an IUT snapshot from a HTML file dump of the FIPS website.
        """
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
    def from_web(cls) -> IUTSnapshot:
        """
        Get an IUT snapshot from the FIPS website right now.
        """
        iut_resp = requests.get(constants.FIPS_IUT_URL)
        if iut_resp.status_code != 200:
            raise ValueError(f"Getting IUT snapshot failed: {iut_resp.status_code}")

        snapshot_date = to_utc(datetime.now())
        return cls.from_page(iut_resp.content, snapshot_date)

    @classmethod
    def from_web_latest(cls) -> IUTSnapshot:
        """
        Get a IUT snapshot from seccerts.org.
        """
        iut_resp = requests.get(config.fips_iut_latest_snapshot)
        if iut_resp.status_code != 200:
            raise ValueError(f"Getting MIP snapshot failed: {iut_resp.status_code}")
        with NamedTemporaryFile() as tmpfile:
            tmpfile.write(iut_resp.content)
            return cls.from_json(tmpfile.name)
