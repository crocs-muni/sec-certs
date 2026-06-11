"""Scraping of Protection Profiles from national CC schemes."""

from __future__ import annotations

import logging
import re
import tempfile
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, Literal, Protocol

import pdftotext
import requests

from sec_certs.constants import REQUEST_TIMEOUT
from sec_certs.serialization.json import ComplexSerializableType

logger = logging.getLogger(__name__)

# NIAP API endpoints
_NIAP_BASE_URL = "https://www.niap-ccevs.org"
_NIAP_PP_API_URL = _NIAP_BASE_URL + "/api/protection-profile/public_pps_all/"
_NIAP_PP_DETAIL_URL = _NIAP_BASE_URL + "/protectionprofiles/{}"
_NIAP_PP_DETAIL_API_URL = _NIAP_BASE_URL + "/api/protection-profile/get_pp_by_id/"
_NIAP_PP_FILE_API_URL = _NIAP_BASE_URL + "/api/file/get_public_files_by_type_and_type_id/"
_NIAP_PP_FILE_DOWNLOAD_URL = _NIAP_BASE_URL + "/api/file/get_public_file/"

# NIAP does not expose a version field; it is encoded as the trailing _v<version> of pp_short_name
# (e.g. PP_APP_v1.4 -> 1.4). Minor parts may carry a letter suffix (2.0E, 1.1a, 1.d), kept verbatim.
_NIAP_VERSION_RE = re.compile(r"[_-][vV](\d+(?:\.[0-9A-Za-z]+)*)$")

_NIAP_TECH_TYPE_TO_CC_CATEGORY: dict[str, str] = {
    "AntiVirus": "Detection Devices and Systems",
    "Application Software": "Other Devices and Systems",
    "BIOS Update": "Other Devices and Systems",
    "Biometrics": "Biometric Systems and Devices",
    "Certificate Authority": "Products for Digital Signatures",
    "DBMS": "Databases",
    "Email Client": "Other Devices and Systems",
    "Encrypted Storage": "Data Protection",
    "Enterprise Security Management": "Detection Devices and Systems",
    "Firewall": "Boundary Protection Devices and Systems",
    "Hardware Platform and Components": "ICs, Smart Cards and Smart Card-Related Devices and Systems",
    "Miscellaneous": "Other Devices and Systems",
    "Mobility": "Mobility",
    "Multi Function Device": "Multi-Function Devices",
    "Network Device": "Network and Network-Related Devices and Systems",
    "Network Encryption": "Network and Network-Related Devices and Systems",
    "Operating System": "Operating Systems",
    "PKI/KMI": "Key Management Systems",
    "Peripheral Switch": "Other Devices and Systems",
    "Redaction Tool": "Other Devices and Systems",
    "Remote Access": "Access Control Devices and Systems",
    "Router": "Network and Network-Related Devices and Systems",
    "SIP Server": "Network and Network-Related Devices and Systems",
    "Smart Card": "ICs, Smart Cards and Smart Card-Related Devices and Systems",
    "Traffic Monitoring": "Detection Devices and Systems",
    "USB Flash Drive": "Data Protection",
    "Virtual Private Network": "Network and Network-Related Devices and Systems",
    "Virtualization": "Other Devices and Systems",
    "VoIP": "Network and Network-Related Devices and Systems",
    "Web Browser": "Other Devices and Systems",
    "Web Server": "Network and Network-Related Devices and Systems",
    "Wireless LAN": "Network and Network-Related Devices and Systems",
    "Wireless Monitoring": "Detection Devices and Systems",
    "Wireless PAN": "Network and Network-Related Devices and Systems",
}

# ANSSI (French) PP catalogue PDF(endpoint)
_ANSSI_PP_CATALOGUE_URL = "https://messervices.cyber.gouv.fr/visas/catalogue-produits-services-profils-de-protection-sites-certifies-qualifies-agrees-anssi.pdf"


@dataclass
class PPSchemeRecord(ComplexSerializableType):
    """
    Intermediate data class representing a Protection Profile scraped from a national scheme.

    Mirrors the fields of ProtectionProfile.WebData. The scraper's responsibility is to fill
    these fields; the merge step uses them to construct and insert new ProtectionProfile objects.
    """

    category: str
    status: Literal["active", "archived"]
    is_collaborative: bool
    name: str
    version: str
    security_level: set[str]
    not_valid_before: date | None
    not_valid_after: date | None
    report_link: str | None
    pp_link: str | None
    scheme: str | None
    maintenances: list[tuple[Any, ...]] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, dct: dict) -> PPSchemeRecord:
        dct = dct.copy()
        if isinstance(dct.get("not_valid_before"), str):
            dct["not_valid_before"] = date.fromisoformat(dct["not_valid_before"])
        if isinstance(dct.get("not_valid_after"), str):
            dct["not_valid_after"] = date.fromisoformat(dct["not_valid_after"])
        dct["maintenances"] = [tuple(m) for m in dct.get("maintenances", [])]
        return cls(**dct)

    def to_enrichment_dict(self) -> dict[str, Any]:
        """Return the scheme-specific enrichment carried into ProtectionProfile.heuristics.scheme_data.

        Holds only the extras not already present on WebData (e.g. NIAP predecessor/successor),
        tagged with the source scheme.
        """
        return {"source_scheme": self.scheme, **self.extra}


class PPScraper(Protocol):
    """Structural interface for PP scheme scrapers.
    Each scheme scraper must implement a scrape() method that returns a list of PPSchemeRecord objects.
    """

    scheme: str

    def scrape(self) -> list[PPSchemeRecord]: ...


class NIAPScraper:
    """Scraper for US Protection Profiles from the NIAP public API."""

    scheme: str = "US"

    @staticmethod
    def _fetch_niap_pps() -> list[dict[str, Any]]:
        logger.info("Fetching Protection Profiles from NIAP API: %s", _NIAP_PP_API_URL)
        resp = requests.get(_NIAP_PP_API_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        logger.info("Fetched %d Protection Profiles from NIAP.", len(data))
        return data

    @staticmethod
    def _fetch_niap_pp_files(pp_id: int) -> list[dict[str, Any]]:
        resp = requests.get(
            _NIAP_PP_FILE_API_URL,
            params={"file_type": "protection-profile", "file_type_id": str(pp_id)},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _fetch_niap_pp_detail(pp_id: int) -> dict[str, Any]:
        """Fetch the per-PP detail record, which (unlike the list endpoint) carries the
        predecessor relation as ``predecessor_id__pp_short_name``."""
        resp = requests.get(
            _NIAP_PP_DETAIL_API_URL,
            params={"pp_id": str(pp_id)},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _parse_niap_date(value: str | None) -> date | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
        except (ValueError, AttributeError):
            return None

    @staticmethod
    def _niap_status_to_cc(status: str) -> Literal["active", "archived"]:
        if status.lower() == "archived":
            return "archived"
        return "active"

    @staticmethod
    def _niap_tech_type_to_cc_category(tech_type: str) -> str:
        return _NIAP_TECH_TYPE_TO_CC_CATEGORY.get(tech_type, "Other Devices and Systems")

    @staticmethod
    def _niap_version_from_short_name(short_name: str | None) -> str:
        match = _NIAP_VERSION_RE.search(short_name or "")
        return match.group(1) if match else ""

    @staticmethod
    def _pick_pp_pdf_file(files: list[dict[str, Any]]) -> dict[str, Any] | None:
        for f in files:
            mime = (f.get("file_mime_type") or "").lower()
            label = (f.get("file_label") or "").lower()
            if mime == "application/pdf" and label.startswith("protection profile"):
                return f
        return None

    @staticmethod
    def _niap_file_download_url(file_id: int) -> str:
        return _NIAP_PP_FILE_DOWNLOAD_URL + "?file_id=" + str(file_id)

    @staticmethod
    def _niap_entry_to_scheme_entry(
        entry: dict[str, Any],
        files: list[dict[str, Any]] | None = None,
        detail: dict[str, Any] | None = None,
    ) -> PPSchemeRecord:
        pp_link: str | None = None
        if files:
            pp_file = NIAPScraper._pick_pp_pdf_file(files)
            if pp_file:
                pp_link = NIAPScraper._niap_file_download_url(pp_file["file_id"])

        # NIAP exposes explicit predecessor/successor relations on the per-PP detail endpoint.
        predecessor = detail.get("predecessor_id__pp_short_name") if detail else None
        successor = detail.get("successor_id__pp_short_name") if detail else None

        return PPSchemeRecord(
            category=NIAPScraper._niap_tech_type_to_cc_category(entry.get("tech_type", "")),
            status=NIAPScraper._niap_status_to_cc(entry.get("status", "Publishing")),
            is_collaborative=False,
            name=entry.get("pp_name", ""),
            version=NIAPScraper._niap_version_from_short_name(entry.get("pp_short_name")),
            security_level=set(),
            not_valid_before=NIAPScraper._parse_niap_date(entry.get("pp_date")),
            not_valid_after=NIAPScraper._parse_niap_date(entry.get("sunset_date")),
            report_link=None,
            pp_link=pp_link,
            scheme="US",
            maintenances=[],
            extra={
                "pp_short_name": entry.get("pp_short_name"),
                "pp_sponsor_id": entry.get("pp_sponsor_id"),
                "pp_transition": entry.get("pp_transition"),
                "cc_version": entry.get("cc_version"),
                "predecessor": predecessor,
                "successor": successor,
            },
        )

    def scrape(self) -> list[PPSchemeRecord]:
        """Fetch all public Protection Profiles from the NIAP API and return as PPSchemeRecord list."""
        try:
            raw_entries = self._fetch_niap_pps()
        except Exception as e:
            logger.error("Failed to fetch NIAP PPs: %s", e)
            return []

        entries: list[PPSchemeRecord] = []
        for raw in raw_entries:
            try:
                pp_id = raw["pp_id"]
                try:
                    files = self._fetch_niap_pp_files(pp_id)
                except Exception as file_err:
                    logger.warning("Failed to fetch files for NIAP PP %s: %s", pp_id, file_err)
                    files = None
                try:
                    detail = self._fetch_niap_pp_detail(pp_id)
                except Exception as detail_err:
                    logger.warning("Failed to fetch detail for NIAP PP %s: %s", pp_id, detail_err)
                    detail = None
                entries.append(self._niap_entry_to_scheme_entry(raw, files=files, detail=detail))
            except Exception as e:
                logger.error("Error processing NIAP PP entry %s: %s", raw.get("pp_name", "?"), e)

        logger.info("Parsed %d PPSchemeRecord objects from NIAP.", len(entries))
        return entries


# PP name keyword → CC category (substring match, case-insensitive)
_ANSSI_PP_NAME_KEYWORD_TO_CC_CATEGORY: dict[str, str] = {
    "smart card": "ICs, Smart Cards and Smart Card-Related Devices and Systems",
    "smartcard": "ICs, Smart Cards and Smart Card-Related Devices and Systems",
    "carte": "ICs, Smart Cards and Smart Card-Related Devices and Systems",
    "globalplatform": "ICs, Smart Cards and Smart Card-Related Devices and Systems",
    "nfc": "ICs, Smart Cards and Smart Card-Related Devices and Systems",
    "mrtd": "ICs, Smart Cards and Smart Card-Related Devices and Systems",
    "travel document": "ICs, Smart Cards and Smart Card-Related Devices and Systems",
    "biometric": "Biometric Systems and Devices",
    "firewall": "Boundary Protection Devices and Systems",
    "network": "Network and Network-Related Devices and Systems",
    "réseau": "Network and Network-Related Devices and Systems",
    "signature": "Products for Digital Signatures",
    "qes": "Products for Digital Signatures",
    "pki": "Key Management Systems",
    "operating system": "Operating Systems",
    "tpm": "Other Devices and Systems",
    "trusted platform": "Other Devices and Systems",
    "iot": "Other Devices and Systems",
    "automotive": "Other Devices and Systems",
    "v2x": "Other Devices and Systems",
}

_ANSSI_CERT_ID_PAT = re.compile(r"(ANSSI-CCPP-\d{4}-\d+(?:M\d+)?)")
_ANSSI_DATE_PAT = re.compile(r"\d{2}/\d{2}/\d{4}")
_ANSSI_CESTI: frozenset[str] = frozenset({"OPPIDA", "THALES", "SERMA"})
# Lines to discard from table blocks: column headers, link placeholders, page numbers
_ANSSI_SKIP_LINE_PAT = re.compile(
    r"^(?:"
    r"Lien vers.*"
    r"|Nom du (?:d[\u00e9e]veloppeur.*|profil.*|commanditaire.*|centre.*|site.*)"
    r"|\(par ordre alphab[\u00e9e]tique\)"
    r"|\(CESTI\)"
    r"|Date de (?:d[\u00e9e]but|fin) de"
    r"|Page \d+ sur \d+"
    r"|produit|d'\u00e9valuation|certificat|certification"
    r"|rapport|rapport de|profil de|protection|GROUP"
    r"|s[\u00e9e]curit[\u00e9e]|certificati|on|cible de|de"
    r"|4\s+Les profils de protection"
    r"|6\.3"
    r"|Profils de protection certifi"
    r")$",
    re.IGNORECASE,
)


class FrenchScraper:
    """Scraper for French Protection Profiles from the ANSSI catalogue PDF."""

    scheme: str = "FR"

    @staticmethod
    def _download_anssi_pdf(dest: Path) -> None:
        """Download the ANSSI PP catalogue PDF to *dest*."""
        logger.info("Downloading ANSSI PP catalogue from %s", _ANSSI_PP_CATALOGUE_URL)
        resp = requests.get(_ANSSI_PP_CATALOGUE_URL, stream=True, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        with dest.open("wb") as fh:
            for chunk in resp.iter_content(chunk_size=65536):
                fh.write(chunk)

    @staticmethod
    def _extract_anssi_sections(pdf_path: Path) -> tuple[str, str]:
        """Return (active_text, archived_text) extracted from the ANSSI catalogue PDF.

        Locates pages by content rather than text position to avoid matching the
        table of contents.
        """
        with pdf_path.open("rb") as fh:
            pdf = list(pdftotext.PDF(fh))

        chapter4_start = -1
        chapter5_start = len(pdf)
        archived_page = -1

        for i, page_text in enumerate(pdf):
            stripped = page_text.lstrip()
            if chapter4_start < 0 and stripped.startswith("4 Les profils de protection"):
                chapter4_start = i
            elif chapter4_start >= 0 and chapter5_start == len(pdf) and re.match(r"5\s+", stripped):
                chapter5_start = i
            if (
                archived_page < 0
                and "Profils de protection certifi" in page_text
                and "archiv" in page_text.lower()
                and "ANSSI-CCPP-" in page_text
            ):
                archived_page = i

        active_text = "\n\f\n".join(pdf[chapter4_start:chapter5_start]) if chapter4_start >= 0 else ""
        archived_text = pdf[archived_page] if archived_page >= 0 else ""

        return active_text, archived_text

    @staticmethod
    def _anssi_pp_name_to_cc_category(name: str) -> str:
        name_lower = name.lower()
        for keyword, category in _ANSSI_PP_NAME_KEYWORD_TO_CC_CATEGORY.items():
            if keyword in name_lower:
                return category
        return "Other Devices and Systems"

    @staticmethod
    def _parse_anssi_date(s: str) -> date | None:
        """Parse a date string in dd/mm/yyyy format, returning None on failure."""
        with suppress(ValueError):
            return datetime.strptime(s.strip(), "%d/%m/%Y").date()
        return None

    @staticmethod
    def _group_into_phrases(lines: list[str]) -> list[str]:
        """Group consecutive non-blank lines into space-joined phrases."""
        phrases: list[str] = []
        current: list[str] = []
        for ln in lines:
            if ln:
                current.append(ln)
            elif current:
                phrases.append(" ".join(current))
                current = []
        if current:
            phrases.append(" ".join(current))
        return phrases

    @staticmethod
    def _parse_anssi_entries(text: str, status: Literal["active", "archived"]) -> list[PPSchemeRecord]:
        """Parse PPSchemeRecord objects from an ANSSI catalogue text section.

        Uses ANSSI-CCPP-* certificate IDs as row anchors, then extracts dates and
        the most likely PP name from the text block preceding each certificate ID.
        Note: the PDF stores links as annotations (not visible text), so
        report_link and pp_link cannot be extracted and are set to None.
        """
        entries: list[PPSchemeRecord] = []

        # Split text on every cert ID; parts alternates [text, certid, text, certid, ..., text]
        parts = _ANSSI_CERT_ID_PAT.split(text)
        cert_ids = parts[1::2]
        before_blocks = parts[0::2]

        for i, cert_id in enumerate(cert_ids):
            block = before_blocks[i]

            # Extract dates from raw block before any cleaning
            dates = _ANSSI_DATE_PAT.findall(block)
            if len(dates) < 2:
                continue
            not_valid_before = FrenchScraper._parse_anssi_date(dates[-2])
            not_valid_after = FrenchScraper._parse_anssi_date(dates[-1])

            # Build cleaned lines, preserving blank lines as phrase separators
            clean_lines: list[str] = []
            for raw_line in block.splitlines():
                stripped = raw_line.strip()
                if not stripped:
                    clean_lines.append("")  # blank line → phrase separator
                elif (
                    not _ANSSI_SKIP_LINE_PAT.match(stripped)
                    and stripped not in _ANSSI_CESTI
                    and not _ANSSI_DATE_PAT.fullmatch(stripped)
                ):
                    clean_lines.append(stripped)

            # Group consecutive non-blank lines into phrases
            phrases = FrenchScraper._group_into_phrases(clean_lines)

            candidates = [p for p in phrases if len(p) > 5]
            if not candidates:
                name = cert_id  # fallback: no text extractable
            else:
                # Prefer phrases that look like protection profile names
                pp_kw = {"profile", "profil", "protection", "pp", "tpm", "trust", "specification"}
                named = [c for c in candidates if any(kw in c.lower() for kw in pp_kw)]
                name = max(named, key=len) if named else max(candidates, key=len)
                # «Lien vers le profil de protection» splits across lines; «protection» is skipped
                # but the PP name starting with «Protection\nProfile» loses its first word → restore it
                if re.match(r"Profile\b", name, re.IGNORECASE) and not re.match(r"Protection\b", name, re.IGNORECASE):
                    name = "Protection " + name

            entries.append(
                PPSchemeRecord(
                    category=FrenchScraper._anssi_pp_name_to_cc_category(name),
                    status=status,
                    is_collaborative=False,
                    name=name,
                    version="",
                    security_level=set(),
                    not_valid_before=not_valid_before,
                    not_valid_after=not_valid_after,
                    report_link=None,
                    pp_link=None,
                    scheme="FR",
                    maintenances=[],
                )
            )

        logger.info("Parsed %d ANSSI PPSchemeRecord objects (status=%s).", len(entries), status)
        return entries

    def scrape(self) -> list[PPSchemeRecord]:
        """Download the ANSSI PP catalogue PDF and return all entries as PPSchemeRecord list."""
        try:
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
                tmp_path = Path(tmp.name)
            self._download_anssi_pdf(tmp_path)
        except Exception as e:
            logger.error("Failed to download ANSSI PP catalogue: %s", e)
            return []

        try:
            active_text, archived_text = self._extract_anssi_sections(tmp_path)
        except Exception as e:
            logger.error("Failed to extract sections from ANSSI PDF: %s", e)
            return []
        finally:
            with suppress(OSError):
                tmp_path.unlink()

        entries: list[PPSchemeRecord] = []
        try:
            entries.extend(self._parse_anssi_entries(active_text, "active"))
        except Exception as e:
            logger.error("Failed to parse ANSSI active PP entries: %s", e)
        try:
            entries.extend(self._parse_anssi_entries(archived_text, "archived"))
        except Exception as e:
            logger.error("Failed to parse ANSSI archived PP entries: %s", e)

        logger.info("Parsed %d PPSchemeRecord objects from ANSSI.", len(entries))
        return entries


PP_SCHEME_SCRAPERS: list[PPScraper] = [NIAPScraper(), FrenchScraper()]
