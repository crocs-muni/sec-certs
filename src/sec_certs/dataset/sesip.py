"""Parsing of the SESIP certificate index from TrustCB"""

from __future__ import annotations

import logging
import re
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Final

import requests
from bs4 import BeautifulSoup, Tag

from sec_certs.constants import SESIP_INDEX_URL
from sec_certs.dataset.dataset import Dataset
from sec_certs.sample.sesip import SESIPCertificate
from sec_certs.serialization.json import ComplexSerializableType, only_backed, serialize
from sec_certs.utils import helpers
from sec_certs.utils.helpers import get_first_16_bytes_sha256
from sec_certs.utils.profiling import staged

if TYPE_CHECKING:
    from sec_certs.converter import PDFConverter

logger = logging.getLogger(__name__)


class SESIPDataset(Dataset[SESIPCertificate], ComplexSerializableType):
    """Dataset of SESIP certificates by TrustCB"""

    INDEX_HTML: Final[str] = "sesip_certificates.html"

    @staticmethod
    def _parse_index_table(page: str) -> list[dict[str, str]]:  # noqa: C901
        """
        Parses the TrustCB index table into one dict per certificate, keyed by the
        field names that SESIPCertificate.IndexData expects.
        """
        column_headers = {
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
        # the only columns whose value is a link; everything else is read as text
        link_fields = frozenset({"cert_link", "st_link"})
        whitespace_re = re.compile(r"\s+")

        def cell_text(cell: Tag) -> str:
            # <br> separates words inside a cell
            return whitespace_re.sub(" ", cell.get_text(" ")).strip()

        def cell_value(cell: Tag, field: str) -> str:
            if field not in link_fields:
                return cell_text(cell)
            link = cell.find("a", href=True)
            if not isinstance(link, Tag):
                return ""
            href = str(link["href"])
            if "/download/" not in href:
                logger.warning(f"Ignoring non-document {field}: {href}")
                return ""
            return href

        table = BeautifulSoup(page, "html5lib").select_one("table.wpDataTable")
        if not table:
            raise ValueError("no wpDataTable element found on the page")

        headers = [cell_text(th) for th in table.select("thead th")]
        unknown = set(headers) - set(column_headers)
        missing = set(column_headers) - set(headers)
        if unknown or missing:
            raise ValueError(f"unexpected columns (extra={sorted(unknown)}, missing={sorted(missing)})")
        fields = [column_headers[h] for h in headers]

        body = table.find("tbody")
        if not isinstance(body, Tag):
            raise ValueError("table has no tbody")

        rows = []
        for row in body.select("tr"):
            cells = row.find_all("td")
            if len(cells) != len(fields):
                logger.warning(f"Skipping a row with {len(cells)} cells, expected {len(fields)}")
                continue
            rows.append({field: cell_value(cell, field) for field, cell in zip(fields, cells)})
        return rows

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
            pass
        try:
            return super().__getitem__(get_first_16_bytes_sha256(item.upper()))
        except KeyError:
            raise KeyError(item) from None

    def _set_local_paths(self) -> None:
        super()._set_local_paths()
        if self.root_dir is None:
            return
        for cert in self:
            cert.set_local_paths(self.cert_dir, self.st_dir)

    def _download_index(self) -> None:
        logger.info(f"Downloading the SESIP certificate index from {SESIP_INDEX_URL}")
        if helpers.download_file(SESIP_INDEX_URL, self.index_path) != requests.codes.ok:
            raise ValueError(f"Could not download the SESIP index from {SESIP_INDEX_URL}")

    def _get_all_certs_from_index(self) -> list[SESIPCertificate]:
        rows = self._parse_index_table(self.index_path.read_text(encoding="utf-8"))
        certs = []
        for row in rows:
            try:
                certs.append(SESIPCertificate.from_index_row(row))
            except ValueError as e:
                logger.warning(f"Skipping a row that failed to parse: {e}")
        return certs

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
