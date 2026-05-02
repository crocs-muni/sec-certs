"""Scraping of Protection Profiles from national CC schemes."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Literal, Protocol

import requests

from sec_certs.constants import REQUEST_TIMEOUT

logger = logging.getLogger(__name__)

# NIAP API endpoints
_NIAP_BASE_URL = "https://www.niap-ccevs.org"
_NIAP_PP_API_URL = _NIAP_BASE_URL + "/api/protection-profile/public_pps_all/"
_NIAP_PP_DETAIL_URL = _NIAP_BASE_URL + "/protectionprofiles/{}"
_NIAP_PP_FILE_API_URL = _NIAP_BASE_URL + "/api/file/get_public_files_by_type_and_type_id/"
_NIAP_PP_FILE_DOWNLOAD_URL = _NIAP_BASE_URL + "/api/file/get_public_file/"

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

# Swedish endpoints
_CSEC_BASE_URL = "https://www.fmv.se"
_CSEC_INDEX_URL = _CSEC_BASE_URL + "/verksamhet/ovrig-verksamhet/csec/certifierade-skyddsprofiler/"

# Mapping
_CSEC_PRODUKTKATEGORI_TO_CC_CATEGORY: dict[str, str] = {
    "Brandvägg": "Boundary Protection Devices and Systems",
    "Krypteringsapplikation": "Data Protection",
    "Nätverksenhet": "Network and Network-Related Devices and Systems",
    "Operativsystem": "Operating Systems",
    "Smartkort": "ICs, Smart Cards and Smart Card-Related Devices and Systems",
    "Åtkomstkontroll": "Access Control Devices and Systems",
    "Databas": "Databases",
    "Biometri": "Biometric Systems and Devices",
    "Protection Profile": "Other Devices and Systems",
}


@dataclass
class PPSchemeEntry:
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


class PPScraper(Protocol):
    """Structural interface for PP scheme scrapers.
    Each scheme scraper must implement a scrape() method that returns a list of PPSchemeEntry objects.
    """

    scheme: str

    def scrape(self) -> list[PPSchemeEntry]: ...


# NIAP scraping helpers


def _fetch_niap_pps() -> list[dict[str, Any]]:
    logger.info("Fetching Protection Profiles from NIAP API: %s", _NIAP_PP_API_URL)
    resp = requests.get(_NIAP_PP_API_URL, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    logger.info("Fetched %d Protection Profiles from NIAP.", len(data))
    return data


def _fetch_niap_pp_files(pp_id: int) -> list[dict[str, Any]]:
    resp = requests.get(
        _NIAP_PP_FILE_API_URL,
        params={"file_type": "protection-profile", "file_type_id": str(pp_id)},
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def _parse_niap_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except (ValueError, AttributeError):
        return None


def _niap_status_to_cc(status: str) -> Literal["active", "archived"]:
    if status.lower() == "archived":
        return "archived"
    return "active"


def _niap_tech_type_to_cc_category(tech_type: str) -> str:
    return _NIAP_TECH_TYPE_TO_CC_CATEGORY.get(tech_type, "Other Devices and Systems")


def _pick_pp_pdf_file(files: list[dict[str, Any]]) -> dict[str, Any] | None:
    for f in files:
        mime = (f.get("file_mime_type") or "").lower()
        label = (f.get("file_label") or "").lower()
        if mime == "application/pdf" and label.startswith("protection profile"):
            return f
    return None


def _niap_file_download_url(file_id: int) -> str:
    return _NIAP_PP_FILE_DOWNLOAD_URL + "?file_id=" + str(file_id)


def _niap_entry_to_scheme_entry(entry: dict[str, Any], files: list[dict[str, Any]] | None = None) -> PPSchemeEntry:
    cc_version = entry.get("cc_version", "")
    security_level: set[str] = {cc_version} if cc_version else set()

    pp_link: str | None = None
    if files:
        pp_file = _pick_pp_pdf_file(files)
        if pp_file:
            pp_link = _niap_file_download_url(pp_file["file_id"])

    return PPSchemeEntry(
        category=_niap_tech_type_to_cc_category(entry.get("tech_type", "")),
        status=_niap_status_to_cc(entry.get("status", "Publishing")),
        is_collaborative=False,
        name=entry.get("pp_name", ""),
        version="",
        security_level=security_level,
        not_valid_before=_parse_niap_date(entry.get("pp_date")),
        not_valid_after=_parse_niap_date(entry.get("sunset_date")),
        report_link=None,
        pp_link=pp_link,
        scheme="US",
        maintenances=[],
    )


class NIAPScraper:
    """Scraper for US Protection Profiles from the NIAP public API."""

    scheme: str = "US"

    def scrape(self) -> list[PPSchemeEntry]:
        """Fetch all public Protection Profiles from the NIAP API and return as PPSchemeEntry list."""
        try:
            raw_entries = _fetch_niap_pps()
        except Exception as e:
            logger.error("Failed to fetch NIAP PPs: %s", e)
            return []

        entries: list[PPSchemeEntry] = []
        for raw in raw_entries:
            try:
                pp_id = raw["pp_id"]
                try:
                    files = _fetch_niap_pp_files(pp_id)
                except Exception as file_err:
                    logger.warning("Failed to fetch files for NIAP PP %s: %s", pp_id, file_err)
                    files = None
                entries.append(_niap_entry_to_scheme_entry(raw, files=files))
            except Exception as e:
                logger.error("Error processing NIAP PP entry %s: %s", raw.get("pp_name", "?"), e)

        logger.info("Parsed %d PPSchemeEntry objects from NIAP.", len(entries))
        return entries


PP_SCHEME_SCRAPERS: list[PPScraper] = [NIAPScraper()]
