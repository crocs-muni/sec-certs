"""Data model for SESIP certificates"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, fields
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import requests

from sec_certs import constants
from sec_certs.cert_rules import sesip_rules
from sec_certs.document.utils import get_view
from sec_certs.sample.certificate import Certificate, logger
from sec_certs.sample.certificate import Heuristics as BaseHeuristics
from sec_certs.sample.certificate import InternalState as BaseInternalState
from sec_certs.sample.certificate import PdfData as BasePdfData
from sec_certs.sample.document_state import DocumentState
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils import helpers
from sec_certs.utils.extract import extract_keywords
from sec_certs.utils.frontpage import parse_sesip_frontpage, strip_legal_form
from sec_certs.utils.helpers import get_first_16_bytes_sha256
from sec_certs.utils.pdf import extract_pdf_metadata

if TYPE_CHECKING:
    from sec_certs.converter import PDFConverter


@dataclass
class InternalState(BaseInternalState, ComplexSerializableType):
    cert: DocumentState = field(default_factory=DocumentState)
    st: DocumentState = field(default_factory=DocumentState)


@dataclass(frozen=True)
class SESIPProfile(ComplexSerializableType):
    family: str
    version: str | None = None  # 1.0
    release: str | None = None  # REL 02, BETA

    def __lt__(self, other: SESIPProfile) -> bool:
        # sets are serialized sorted
        return (self.family, self.version or "", self.release or "") < (
            other.family,
            other.version or "",
            other.release or "",
        )


with (Path(__file__).parent.parent / "sesip_profiles.json").open(encoding="utf-8") as f:
    SESIP_PROFILES: Final[dict[str, dict[str, Any]]] = {
        p["family"]: {**p, "pattern": re.compile(p["pattern"], re.IGNORECASE)} for p in json.load(f)
    }
_NEXT_PROFILE_RE: Final = re.compile(r"profile\s+for", re.IGNORECASE)
_MARKED_VERSION_RE: Final = re.compile(r"(?:version|\bv)\s*\.?\s*(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
_BARE_VERSION_RE: Final = re.compile(r"(?<![\d.])(\d+\.\d+)(?![\d.x])")
_RELEASE_RE: Final = re.compile(r"[\s,]*(BETA|draft)?[\s,]*(?:REL\s*(\d+))?", re.IGNORECASE)


def _profile_version(text: str, start: int) -> tuple[str | None, str | None]:
    end = m.start() if (m := _NEXT_PROFILE_RE.search(text, start)) else len(text)
    tail = text[start:end]
    version = _MARKED_VERSION_RE.search(tail) or _BARE_VERSION_RE.search(tail)
    if not version:
        return None, None
    stage, rel = r.groups() if (r := _RELEASE_RE.match(tail, version.end())) else (None, None)
    release = " ".join(x for x in (stage and stage.upper(), rel and f"REL {int(rel):02d}") if x)
    return version.group(1), release or None


class SESIPCertificate(
    Certificate["SESIPCertificate", "SESIPCertificate.Heuristics", "SESIPCertificate.PdfData", "InternalState"],
    ComplexSerializableType,
):
    @dataclass
    class IndexData(ComplexSerializableType):
        """row of the TrustCB index table"""

        cert_id: str
        product: str
        developer: str | None = None
        evaluator: str | None = None
        assurance_level: str | None = None  # not augmented
        standard: str | None = None
        status: str | None = None
        issue_date: date | None = None
        cert_link: str | None = None
        st_link: str | None = None

        @classmethod
        def from_row(cls, row: dict[str, str]) -> SESIPCertificate.IndexData:
            # empty cell defaults to none
            return cls.from_dict({k: v for k, v in row.items() if v})

        @classmethod
        def from_dict(cls, dct: dict) -> SESIPCertificate.IndexData:
            known = {f.name for f in fields(cls)}
            values = {k: v for k, v in dct.items() if k in known}
            for required in ("cert_id", "product"):
                if not values.get(required):
                    raise ValueError(f"index row has no {required}")
            raw_date = values.get("issue_date")
            if isinstance(raw_date, str):
                try:
                    values["issue_date"] = date.fromisoformat(raw_date)
                except ValueError:
                    logger.warning(f"Ignoring an unparsable issue_date: {raw_date!r}")
                    values["issue_date"] = None
            return cls(**values)

    @dataclass
    class PdfData(BasePdfData, ComplexSerializableType):
        cert_metadata: dict[str, Any] | None = field(default=None)
        st_metadata: dict[str, Any] | None = field(default=None)
        cert_frontpage: dict[str, Any] | None = field(default=None)
        st_keywords: dict[str, Any] | None = field(default=None)

    @dataclass
    class Heuristics(BaseHeuristics, ComplexSerializableType):
        cert_lab: list[str] | None = field(default=None)
        status: str | None = field(default=None)  # active, expired, withdrawn, terminated
        prev_certificates: list[str] | None = field(default=None)
        next_certificates: list[str] | None = field(default=None)
        sesip_profiles: set[SESIPProfile] | None = field(default=None)
        # against a PSA profile, not PSA certificate
        psa_profile_level: int | None = field(default=None)
        psa_rot_component_profile_level: int | None = field(default=None)

    def __init__(
        self,
        index_data: SESIPCertificate.IndexData,
        pdf_data: SESIPCertificate.PdfData | None = None,
        heuristics: SESIPCertificate.Heuristics | None = None,
        state: InternalState | None = None,
    ):
        super().__init__()
        self.index_data = index_data
        self.pdf_data = pdf_data if pdf_data else SESIPCertificate.PdfData()
        self.heuristics = heuristics if heuristics else SESIPCertificate.Heuristics()
        self.state = state if state else InternalState()

    @classmethod
    def from_index_row(cls, row: dict[str, str]) -> SESIPCertificate:
        return cls(cls.IndexData.from_row(row))

    @property
    def cert_id(self) -> str:
        return self.index_data.cert_id

    @property
    def dgst(self) -> str:
        return get_first_16_bytes_sha256(self.cert_id)

    @property
    def name(self) -> str:  # type: ignore
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
            + str(self.index_data.assurance_level)
        )

    @property
    def has_separate_st(self) -> bool:
        # withheld certificates have only cert file
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
            logger.error(f"Cert dgst: {self.dgst} failed to download the {label} from {url}, code {exit_code}")
            return

        doc.download_ok = True
        source_hash = helpers.get_sha256_filepath(doc.source_path)
        if source_hash != doc.source_hash:
            doc.reset_conversion()
        doc.source_hash = source_hash

    @staticmethod
    def convert_documents(cert: SESIPCertificate, converter: PDFConverter, fresh: bool = True) -> SESIPCertificate:
        for doc, label in ((cert.state.cert, "certificate"), (cert.state.st, "security target")):
            if doc.is_ok_to_convert(fresh):
                cert._convert_document(converter, doc, label)
        return cert

    def _convert_document(self, converter: PDFConverter, doc: DocumentState, label: str) -> None:
        doc.reset_conversion()

        doc.txt_path.parent.mkdir(parents=True, exist_ok=True)
        doc.json_path.parent.mkdir(parents=True, exist_ok=True)

        if not converter.convert(doc.source_path, doc.txt_path, doc.json_path):
            logger.error(f"Cert dgst: {self.dgst} failed to convert the {label} to txt")
            return

        doc.convert_ok = True
        doc.txt_hash = helpers.get_sha256_filepath(doc.txt_path)
        # only converters with HAS_JSON_OUTPUT write one
        doc.json_hash = helpers.get_sha256_filepath(doc.json_path) if doc.json_path.exists() else None

    @staticmethod
    def extract_documents_metadata(cert: SESIPCertificate) -> SESIPCertificate:
        for doc, attr in ((cert.state.cert, "cert_metadata"), (cert.state.st, "st_metadata")):
            if not doc.is_ok_to_extract():
                continue
            setattr(cert.pdf_data, attr, None)
            try:
                setattr(cert.pdf_data, attr, extract_pdf_metadata(doc.source_path))
            except ValueError:
                doc.extract_ok = False
        return cert

    @staticmethod
    def extract_cert_frontpage(cert: SESIPCertificate) -> SESIPCertificate:
        if not cert.state.cert.is_ok_to_extract():
            return cert
        cert.pdf_data.cert_frontpage = None
        try:
            cert.pdf_data.cert_frontpage = parse_sesip_frontpage(get_view(cert.state.cert).get_full_text())
        except (OSError, ValueError) as e:
            logger.error(f"Cert dgst: {cert.dgst} failed to parse the certificate frontpage: {e}")
            cert.state.cert.extract_ok = False
        return cert

    @staticmethod
    def extract_st_keywords(cert: SESIPCertificate) -> SESIPCertificate:
        if not cert.state.st.is_ok_to_extract():
            return cert
        cert.pdf_data.st_keywords = None
        keywords = extract_keywords(get_view(cert.state.st), sesip_rules)
        if keywords is None:
            logger.error(f"Cert dgst: {cert.dgst} failed to extract keywords from the security target")
            cert.state.st.extract_ok = False
        else:
            cert.pdf_data.st_keywords = keywords
        return cert

    def compute_heuristics_cert_lab(self) -> None:
        frontpage = self.pdf_data.cert_frontpage or {}
        lab = self.index_data.evaluator or frontpage.get(constants.TAG_CERT_LAB)
        name = strip_legal_form(lab) if lab else None
        self.heuristics.cert_lab = [name] if name else None

    def compute_heuristics_status(self) -> None:
        table_status = (self.index_data.status or "").lower()
        if table_status in ("terminated", "withdrawn"):
            self.heuristics.status = table_status
        elif self.index_data.product.lower().startswith("withdrawn"):
            self.heuristics.status = "withdrawn"
        else:
            expiry = (self.pdf_data.cert_frontpage or {}).get("expiry_date") or ""
            try:
                # same rule as EUCC - valid if the expiry date is in the future
                self.heuristics.status = "active" if date.fromisoformat(expiry) > date.today() else "expired"
            except (TypeError, ValueError):
                self.heuristics.status = None

    def compute_heuristics_sesip_profiles(self) -> None:
        text = (self.pdf_data.cert_frontpage or {}).get("sesip_profile") or ""
        found = {
            SESIPProfile(name, *_profile_version(text, m.end()))
            for name, profile in SESIP_PROFILES.items()
            if (m := profile["pattern"].search(text))
        }
        if text and not found:
            logger.warning(f"Cert dgst: {self.dgst} has an unknown SESIP profile: {text}")
        self.heuristics.sesip_profiles = found or None

    def compute_heuristics_psa_profile_levels(self) -> None:
        entries = [e for p in self.heuristics.sesip_profiles or [] if (e := SESIP_PROFILES.get(p.family))]
        levels = [(e["psa_level"], e["psa_rot_component"]) for e in entries if e["psa_level"]]
        self.heuristics.psa_profile_level = min((lvl for lvl, rot in levels if not rot), default=None)
        self.heuristics.psa_rot_component_profile_level = min((lvl for lvl, rot in levels if rot), default=None)

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
