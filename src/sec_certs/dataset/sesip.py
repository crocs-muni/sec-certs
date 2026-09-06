"""Parsing of the SESIP certificate index from TrustCB"""

from __future__ import annotations

import html
import logging
import re
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Final

import requests

from sec_certs.dataset.dataset import Dataset
from sec_certs.sample.sesip import SESIPCertificate
from sec_certs.serialization.json import ComplexSerializableType, only_backed, serialize
from sec_certs.utils import helpers
from sec_certs.utils import parallel_processing as cert_processing
from sec_certs.utils.helpers import get_first_16_bytes_sha256
from sec_certs.utils.profiling import staged

if TYPE_CHECKING:
    from sec_certs.converter import PDFConverter

logger = logging.getLogger(__name__)

INDEX_URL = "https://trustcb.com/iot/sesip/sesip-certificates/"

# header to field name
COLUMN_HEADERS: dict[str, str] = {
    "Cert. ID": "cert_id",
    "Issue Date": "issue_date",
    "Product": "product",
    "Developer": "developer",
    "Evaluator": "evaluator",
    "Compliance": "compliance",
    "Standard": "standard",
    "Status": "status",
    "Cert": "cert_link",
    "ST": "st_link",
}

_TABLE_RE = re.compile(r'<table[^>]*class="[^"]*wpDataTable[^"]*"[^>]*>(.*?)</table>', re.DOTALL)
_TBODY_RE = re.compile(r"<tbody>(.*?)</tbody>", re.DOTALL)
_ROW_RE = re.compile(r"<tr[^>]*>(.*?)</tr>", re.DOTALL)
_TH_RE = re.compile(r"<th[^>]*>(.*?)</th>", re.DOTALL)
_TD_RE = re.compile(r"<td[^>]*>(.*?)</td>", re.DOTALL)
_HREF_RE = re.compile(r'href="([^"]+)"')
_BR_RE = re.compile(r"<br\s*/?>", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")


class UnexpectedIndexSchema(ValueError):
    """The portal table no longer has the columns we know how to read"""


def _cell_text(cell: str) -> str:
    # <br> separates words inside a cell
    return re.sub(r"\s+", " ", html.unescape(_TAG_RE.sub("", _BR_RE.sub(" ", cell)))).strip()


def _cell_value(cell: str) -> str:
    match = _HREF_RE.search(cell)
    return html.unescape(match.group(1)) if match else _cell_text(cell)


def parse_index_table(page: str) -> list[dict[str, str]]:
    # parsing the index table into one dict per certificate

    # return = rows keyed by the field names in :data:`COLUMN_HEADERS`
    table = _TABLE_RE.search(page)
    if not table:
        raise UnexpectedIndexSchema("no wpDataTable element found on the page")

    headers = [_cell_text(th) for th in _TH_RE.findall(table.group(1))]
    unknown = set(headers) - set(COLUMN_HEADERS)
    missing = set(COLUMN_HEADERS) - set(headers)
    if unknown or missing:
        raise UnexpectedIndexSchema(f"unexpected columns (extra={sorted(unknown)}, missing={sorted(missing)})")
    fields = [COLUMN_HEADERS[h] for h in headers]

    body = _TBODY_RE.search(table.group(1))
    if not body:
        raise UnexpectedIndexSchema("table has no tbody")

    rows = []
    for row in _ROW_RE.findall(body.group(1)):
        cells = _TD_RE.findall(row)
        if len(cells) != len(fields):
            raise UnexpectedIndexSchema(f"row has {len(cells)} cells, expected {len(fields)}")
        rows.append(dict(zip(fields, (_cell_value(c) for c in cells))))
    return rows


class SESIPDataset(Dataset[SESIPCertificate], ComplexSerializableType):
    """Dataset of SESIP certificates by TrustCB"""

    INDEX_HTML: Final[str] = "sesip_certificates.html"

    @property
    @only_backed(throw=False)
    def cert_dir(self) -> Path:
        return self.certs_dir / "cert"

    @property
    @only_backed(throw=False)
    def st_dir(self) -> Path:
        return self.certs_dir / "st"

    @property
    @only_backed(throw=False)
    def index_path(self) -> Path:
        return self.web_dir / self.INDEX_HTML

    def __getitem__(self, item: str) -> SESIPCertificate:
        try:
            return super().__getitem__(item)
        except KeyError:
            return super().__getitem__(get_first_16_bytes_sha256(item))

    def _set_local_paths(self) -> None:
        super()._set_local_paths()
        if self.root_dir is None:
            return
        for cert in self:
            cert.set_local_paths(self.cert_dir, self.st_dir)

    def _download_index(self) -> None:
        logger.info(f"Downloading the SESIP certificate index from {INDEX_URL}")
        if helpers.download_file(INDEX_URL, self.index_path) != requests.codes.ok:
            raise ValueError(f"Could not download the SESIP index from {INDEX_URL}")

    def _get_all_certs_from_index(self) -> list[SESIPCertificate]:
        rows = parse_index_table(self.index_path.read_text(encoding="utf-8"))
        return [SESIPCertificate.from_index_row(row) for row in rows]

    @serialize
    @staged(logger, "Downloading and processing certificates.")
    @only_backed()
    def get_certs_from_web(self, to_download: bool = True, keep_metadata: bool = True) -> None:
        self.web_dir.mkdir(parents=True, exist_ok=True)

        if to_download:
            self._download_index()
        if not self.index_path.exists():
            raise ValueError(f"No index at {self.index_path}, run with to_download=True first")

        self.certs = {x.dgst: x for x in self._get_all_certs_from_index()}
        logger.info(f"Dataset contains {len(self)} certificates")

        if not keep_metadata:
            shutil.rmtree(self.web_dir)

        self._set_local_paths()
        self.state.meta_sources_parsed = True

    def _download_all_artifacts_body(self, fresh: bool = True) -> None:
        self._download_certificates(fresh)

    @staged(logger, "Downloading SESIP certs and STs")
    def _download_certificates(self, fresh: bool = True) -> None:
        for folder in (self.cert_dir, self.st_dir):
            (folder / "pdf").mkdir(parents=True, exist_ok=True)

        certs_to_process = [
            x
            for x in self
            if x.state.cert.is_ok_to_download(fresh) or (x.has_separate_st and x.state.st.is_ok_to_download(fresh))
        ]
        if not fresh and certs_to_process:
            logger.info(f"Retrying {len(certs_to_process)} certificates for which download failed.")

        cert_processing.process_parallel(
            SESIPCertificate.download_artifacts,
            certs_to_process,
            kwargs={"fresh": fresh},
            progress_bar_desc="Downloading PDFs",
        )

    def _convert_all_pdfs_body(self, converter: type[PDFConverter], fresh: bool = True) -> None:
        raise NotImplementedError("not implemented yet.")

    def extract_data(self) -> None:
        raise NotImplementedError("not implemented yet.")

    def _compute_heuristics_body(self) -> None:
        raise NotImplementedError("not implemented yet.")
