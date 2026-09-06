"""Data model for SESIP certificates"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from datetime import date
from pathlib import Path

from sec_certs.sample.certificate import Certificate
from sec_certs.sample.certificate import Heuristics as BaseHeuristics
from sec_certs.sample.certificate import PdfData as BasePdfData
from sec_certs.sample.document_state import DocumentState
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils.helpers import get_first_16_bytes_sha256


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
