"""Parsing of the SESIP certificate index from TrustCB"""

from __future__ import annotations

import logging
import re
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Final

import requests
from bs4 import BeautifulSoup, Tag

from sec_certs.dataset.dataset import Dataset
from sec_certs.sample.sesip import SESIPCertificate
from sec_certs.serialization.json import ComplexSerializableType, only_backed, serialize
from sec_certs.utils import helpers
from sec_certs.utils.helpers import get_first_16_bytes_sha256
from sec_certs.utils.profiling import staged

if TYPE_CHECKING:
    from sec_certs.converter import PDFConverter

logger = logging.getLogger(__name__)

# review(jakub): this should go to the sec_certs.constants
INDEX_URL = "https://trustcb.com/iot/sesip/sesip-certificates/"

# review(jakub): this is used just by the parse_index_table; if you want to have it as a constant, I'd move it closer to the place where it
#                it is actually used. But personally, I would just define in the function as I dont see a reason to have it in this scope at all.
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

_WHITESPACE_RE = re.compile(r"\s+")


# review(jakub): I'd move this whole block (_cell_text, _cell_value, parse_index_table) into SESIPDataset
#                as private staticmethods, It's only called from _get_all_certs_from_index and it isn't reusable
#                outside SESIP currently.
#                Every other dataset keeps its index parsing on the class: CCDataset._parse_single_html,
#                ProtectionProfileDataset._parse_single_html, FIPSDataset._get_certificates_from_html,
#                EUCCDataset._parse_page_metadata.
def _cell_text(cell: Tag) -> str:
    # <br> separates words inside a cell
    return _WHITESPACE_RE.sub(" ", cell.get_text(" ")).strip()


def _cell_value(cell: Tag) -> str:
    link = cell.find("a", href=True)
    return str(link["href"]) if isinstance(link, Tag) else _cell_text(cell)


# review(Claude Code): Terminated certs are the edge case that breaks it:
#                SESIP-2100003-01 has <a href=".../policies-procedures/certification-terminated">
#                <button>TERMINATED</button></a> in the Cert column, so cert_link ends up as the
#                policy page instead of None and we would download an HTML page as the certificate.
def parse_index_table(page: str) -> list[dict[str, str]]:
    # parsing the index table into one dict per certificate

    # return = rows keyed by the field names in :data:`COLUMN_HEADERS`
    table = BeautifulSoup(page, "html5lib").select_one("table.wpDataTable")
    if not table:
        raise ValueError("no wpDataTable element found on the page")

    headers = [_cell_text(th) for th in table.select("thead th")]
    unknown = set(headers) - set(COLUMN_HEADERS)
    missing = set(COLUMN_HEADERS) - set(headers)
    if unknown or missing:
        raise ValueError(f"unexpected columns (extra={sorted(unknown)}, missing={sorted(missing)})")
    fields = [COLUMN_HEADERS[h] for h in headers]

    body = table.find("tbody")
    if not isinstance(body, Tag):
        raise ValueError("table has no tbody")

    rows = []
    for row in body.select("tr"):
        cells = row.find_all("td")
        if len(cells) != len(fields):
            raise ValueError(f"row has {len(cells)} cells, expected {len(fields)}")
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
    def get_certs_from_web(
        self, to_download: bool = True, keep_metadata: bool = True, carry_processing_results: bool = False
    ) -> None:
        self.web_dir.mkdir(parents=True, exist_ok=True)

        if to_download:
            self._download_index()
        if not self.index_path.exists():
            raise ValueError(f"No index at {self.index_path}, run with to_download=True first")

        old_certs = self.certs
        self.certs = {x.dgst: x for x in self._get_all_certs_from_index()}
        logger.info(f"Dataset contains {len(self)} certificates")

        if not keep_metadata:
            shutil.rmtree(self.web_dir)

        if carry_processing_results:
            self._carry_processing_results(old_certs)
        else:
            self._set_local_paths()
        self.state.meta_sources_parsed = True

    def _download_all_artifacts_body(self, fresh: bool = True) -> None:
        raise NotImplementedError("not implemented yet.")

    def _convert_all_pdfs_body(self, converter: type[PDFConverter], fresh: bool = True) -> None:
        raise NotImplementedError("not implemented yet.")

    def extract_data(self, fresh: bool = True) -> None:
        raise NotImplementedError("not implemented yet.")

    def _compute_heuristics_body(self) -> None:
        raise NotImplementedError("not implemented yet.")
