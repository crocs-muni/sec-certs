from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, ClassVar, Literal, Protocol

import requests

from sec_certs.constants import REQUEST_TIMEOUT
from sec_certs.serialization.json import ComplexSerializableType

logger = logging.getLogger(__name__)


@dataclass
class PPSchemeRecord(ComplexSerializableType):
    """
    Intermediate data class representing a Protection Profile scraped from a national scheme.
    Mirrors the fields of ProtectionProfile.WebData.
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
        # Return the scheme-specific enrichment carried into ProtectionProfile.scheme_metadata.
        return {"source_scheme": self.scheme, **self.extra}


class PPScraper(Protocol):
    """
    Structural interface for PP scheme scrapers.
    Each scheme scraper must implement a scrape() method that returns a list of PPSchemeRecord objects
    """

    scheme: str

    def scrape(self) -> list[PPSchemeRecord]: ...


class NIAPScraper:
    """Scraper for US Protection Profiles from the NIAP public API."""

    scheme: str = "US"
    _NIAP_BASE_URL: ClassVar[str] = "https://www.niap-ccevs.org"
    _NIAP_PP_API_URL: ClassVar[str] = _NIAP_BASE_URL + "/api/protection-profile/public_pps_all/"
    _NIAP_PP_DETAIL_API_URL: ClassVar[str] = _NIAP_BASE_URL + "/api/protection-profile/get_pp_by_id/"
    _NIAP_PP_FILE_API_URL: ClassVar[str] = _NIAP_BASE_URL + "/api/file/get_public_files_by_type_and_type_id/"
    _NIAP_PP_FILE_DOWNLOAD_URL: ClassVar[str] = _NIAP_BASE_URL + "/api/file/get_public_file/"
    _NIAP_VERSION_RE: ClassVar[re.Pattern[str]] = re.compile(r"[_-][vV](\d+(?:\.[0-9A-Za-z]+)*)$")
    _NIAP_TECH_TYPE_TO_CC_CATEGORY: ClassVar[dict[str, str]] = {
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

    @staticmethod
    def _fetch_niap_pps() -> list[dict[str, Any]]:
        logger.info("Fetching Protection Profiles from NIAP API: %s", NIAPScraper._NIAP_PP_API_URL)
        resp = requests.get(NIAPScraper._NIAP_PP_API_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        logger.info("Fetched %d Protection Profiles from NIAP.", len(data))
        return data

    @staticmethod
    def _fetch_niap_pp_files(pp_id: int) -> list[dict[str, Any]]:
        resp = requests.get(
            NIAPScraper._NIAP_PP_FILE_API_URL,
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
            NIAPScraper._NIAP_PP_DETAIL_API_URL,
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
    def _niap_status_process(status: str, sunset: date | None) -> Literal["active", "archived"]:
        # The list endpoint's status is almost always Publishing while NIAP treats a PP as archived
        if status.lower() == "archived" or (sunset is not None and sunset < date.today()):
            return "archived"
        return "active"

    @staticmethod
    def _niap_tech_type_to_cc_category(tech_type: str) -> str:
        return NIAPScraper._NIAP_TECH_TYPE_TO_CC_CATEGORY.get(tech_type, "Other Devices and Systems")

    @staticmethod
    def _niap_version_from_short_name(short_name: str | None) -> str:
        match = NIAPScraper._NIAP_VERSION_RE.search(short_name or "")
        return match.group(1) if match else ""

    @staticmethod
    def _niap_is_collaborative(name: str | None) -> bool:
        # NIAP has no collaborative flag, now its brought from name
        return (name or "").lower().startswith("collaborative")

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
        return NIAPScraper._NIAP_PP_FILE_DOWNLOAD_URL + "?file_id=" + str(file_id)

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

        # NIAP exposes explicit predecessor/successor relations on the per-PP detail endpoint
        predecessor = detail.get("predecessor_id__pp_short_name") if detail else None
        successor = detail.get("successor_id__pp_short_name") if detail else None

        not_valid_after = NIAPScraper._parse_niap_date(entry.get("sunset_date"))

        return PPSchemeRecord(
            category=NIAPScraper._niap_tech_type_to_cc_category(entry.get("tech_type", "")),
            status=NIAPScraper._niap_status_process(entry.get("status", "Publishing"), not_valid_after),
            is_collaborative=NIAPScraper._niap_is_collaborative(entry.get("pp_name")),
            name=entry.get("pp_name", ""),
            version=NIAPScraper._niap_version_from_short_name(entry.get("pp_short_name")),
            security_level=set(),
            not_valid_before=NIAPScraper._parse_niap_date(entry.get("pp_date")),
            not_valid_after=not_valid_after,
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


PP_SCHEME_SCRAPERS: list[PPScraper] = [NIAPScraper()]
