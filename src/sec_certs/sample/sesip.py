"""Data model for SESIP certificates"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, fields
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING

import requests

from sec_certs.sample.certificate import Certificate
from sec_certs.sample.certificate import Heuristics as BaseHeuristics
from sec_certs.sample.certificate import PdfData as BasePdfData
from sec_certs.sample.document_state import DocumentState
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils import helpers
from sec_certs.utils.helpers import get_first_16_bytes_sha256

if TYPE_CHECKING:
    from sec_certs.converter import PDFConverter

logger = logging.getLogger(__name__)

PDF_MAGIC = b"%PDF-"


@dataclass
class InternalState(ComplexSerializableType):
    # two artifacts per certificate
    cert: DocumentState = field(default_factory=DocumentState)
    st: DocumentState = field(default_factory=DocumentState)


class SESIPCertificate(
    Certificate["SESIPCertificate", "SESIPCertificate.Heuristics", "SESIPCertificate.PdfData"],
    ComplexSerializableType,
):
    # single sesip CERT

    @dataclass
    class IndexData(ComplexSerializableType):
        """row of the TrustCB index table"""

        product: str | None = None
        developer: str | None = None
        evaluator: str | None = None
        compliance: str | None = None  # not augmented
        standard: str | None = None
        status: str | None = None
        issue_date: date | None = None
        cert_link: str | None = None
        st_link: str | None = None

        @classmethod
        def from_row(cls, row: dict[str, str]) -> SESIPCertificate.IndexData:
            known = {f.name for f in fields(cls)}
            # empty cell defaults to none
            return cls.from_dict({k: v.strip() for k, v in row.items() if k in known and v.strip()})

        @classmethod
        def from_dict(cls, dct: dict) -> SESIPCertificate.IndexData:
            values = dict(dct)
            if isinstance(values.get("issue_date"), str):
                values["issue_date"] = date.fromisoformat(values["issue_date"])
            return cls(**values)

    @dataclass
    class PdfData(BasePdfData, ComplexSerializableType):
        # data from certificate pdf
        pass

    @dataclass
    class Heuristics(BaseHeuristics, ComplexSerializableType):
        pass

    def __init__(
        self,
        cert_id: str,
        index_data: SESIPCertificate.IndexData | None = None,
        pdf_data: SESIPCertificate.PdfData | None = None,
        heuristics: SESIPCertificate.Heuristics | None = None,
        state: InternalState | None = None,
    ):
        super().__init__()
        self.cert_id = cert_id
        self.index_data = index_data if index_data else SESIPCertificate.IndexData()
        self.pdf_data = pdf_data if pdf_data else SESIPCertificate.PdfData()
        self.heuristics = heuristics if heuristics else SESIPCertificate.Heuristics()
        self.state = state if state else InternalState()

    @classmethod
    def from_index_row(cls, row: dict[str, str]) -> SESIPCertificate:
        if not row.get("cert_id"):
            raise ValueError("row has no cert_id, which is the primary key")
        return cls(cert_id=row["cert_id"], index_data=cls.IndexData.from_row(row))

    @property
    def dgst(self) -> str:
        return get_first_16_bytes_sha256(self.cert_id)

    @property
    def name(self) -> str | None:  # type: ignore
        return self.index_data.product

    @property
    def manufacturer(self) -> str | None:  # type: ignore
        return self.index_data.developer

    @property
    def label_studio_title(self) -> str:
        return (
            "Product: "
            + str(self.index_data.product)
            + "\n"
            + "Developer: "
            + str(self.index_data.developer)
            + "\n"
            + "Assurance: "
            + str(self.index_data.compliance)
        )

    @property
    def has_separate_st(self) -> bool:
        # unpublished certs have two same cert/st links
        return bool(self.index_data.st_link) and self.index_data.st_link != self.index_data.cert_link

    @staticmethod
    def download_artifacts(cert: SESIPCertificate, fresh: bool = True) -> SESIPCertificate:
        if cert.state.cert.is_ok_to_download(fresh):
            cert._download_document(cert.index_data.cert_link, cert.state.cert, "certificate")
        if cert.has_separate_st and cert.state.st.is_ok_to_download(fresh):
            cert._download_document(cert.index_data.st_link, cert.state.st, "security target")
        return cert

    def _download_document(self, url: str | None, doc: DocumentState, label: str) -> None:
        doc.download_ok = False
        if not url:
            logger.warning(f"Cert dgst: {self.dgst} has no link to the {label}")
            return

        doc.source_path.parent.mkdir(parents=True, exist_ok=True)
        if (exit_code := helpers.download_file(url, doc.source_path)) != requests.codes.ok:
            logger.error(f"Cert dgst: {self.dgst} failed to download {label} from {url}, code {exit_code}")
            return

        if not self._is_pdf(doc.source_path):
            logger.error(f"Cert dgst: {self.dgst} got a non-pdf response for the {label} from {url}")
            doc.source_path.unlink(missing_ok=True)
            return

        doc.download_ok = True
        doc.source_hash = helpers.get_sha256_filepath(doc.source_path)

    @staticmethod
    def convert_documents(cert: SESIPCertificate, converter: PDFConverter) -> SESIPCertificate:
        for doc, label in ((cert.state.cert, "certificate"), (cert.state.st, "security target")):
            if doc.is_ok_to_convert():
                cert._convert_document(converter, doc, label)
        return cert

    def _convert_document(self, converter: PDFConverter, doc: DocumentState, label: str) -> None:
        doc.txt_path.parent.mkdir(parents=True, exist_ok=True)
        doc.json_path.parent.mkdir(parents=True, exist_ok=True)

        doc.convert_ok = converter.convert(doc.source_path, doc.txt_path, doc.json_path)
        if not doc.convert_ok:
            logger.error(f"Cert dgst: {self.dgst} failed to convert the {label} pdf to txt")
            return

        doc.txt_hash = helpers.get_sha256_filepath(doc.txt_path)
        doc.json_hash = helpers.get_sha256_filepath(doc.json_path) if doc.json_path.exists() else None

    @staticmethod
    def _is_pdf(path: Path) -> bool:
        with path.open("rb") as handle:
            return handle.read(len(PDF_MAGIC)) == PDF_MAGIC

    def set_local_paths(self, cert_dir: str | Path, st_dir: str | Path) -> None:
        for doc, folder in ((self.state.cert, Path(cert_dir)), (self.state.st, Path(st_dir))):
            doc.source_path = (folder / "pdf" / self.dgst).with_suffix(".pdf")
            doc.txt_path = (folder / "txt" / self.dgst).with_suffix(".txt")
            doc.json_path = (folder / "json" / self.dgst).with_suffix(".json")

    def __hash__(self) -> int:
        return hash(self.dgst)

    def __repr__(self) -> str:
        return f"SESIPCertificate({self.cert_id})"

    def __str__(self) -> str:
        return f"{self.cert_id}: {self.index_data.product or '<unknown product>'}"
