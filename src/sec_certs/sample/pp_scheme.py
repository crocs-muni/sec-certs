"""Scraping of Protection Profiles from national CC schemes."""

from __future__ import annotations

import logging
import re
from contextlib import suppress
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
_CSEC_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Accept-Language": "en-US,en;q=0.9",
}

# Swedish category mapping
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

# Korean ITSCC endpoints
_ITSCC_BASE_URL = "https://itscc.kr"
_ITSCC_ACTIVE_LIST_URL = _ITSCC_BASE_URL + "/pprof/listA.do"
_ITSCC_ARCHIVED_LIST_URL = _ITSCC_BASE_URL + "/pprof/listD.do"
_ITSCC_VIEW_URL = _ITSCC_BASE_URL + "/pprof/view.do"
_ITSCC_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Accept-Language": "en-US,en;q=0.9",
}

# ANSSI (French) PP catalogue PDF(endpoint)
_ANSSI_PP_CATALOGUE_URL = "https://messervices.cyber.gouv.fr/visas/catalogue-produits-services-profils-de-protection-sites-certifies-qualifies-agrees-anssi.pdf"

# "Type of PP" field on the English detail page → CC category
_ITSCC_TYPE_TO_CC_CATEGORY: dict[str, str] = {
    # Values observed from live detail pages (Type of PP field)
    "Access Control in OS": "Access Control Devices and Systems",
    "DB Access Control": "Access Control Devices and Systems",
    "DB Encryption": "Data Protection",
    "DLP": "Data Protection",
    "Electronic Document Encryption": "Data Protection",
    "ESM": "Detection Devices and Systems",
    "IPS": "Detection Devices and Systems",
    "MDM": "Mobility",
    "NAC": "Access Control Devices and Systems",
    "Network Device": "Network and Network-Related Devices and Systems",
    "SSO": "Access Control Devices and Systems",
    "VoIP Firewall": "Network and Network-Related Devices and Systems",
    "Web Application Firewall": "Boundary Protection Devices and Systems",
    "WIPS": "Detection Devices and Systems",
    "Wireless LAN Authentication": "Network and Network-Related Devices and Systems",
    # Additional values potentially present in archived pages
    "Firewall": "Boundary Protection Devices and Systems",
    "Operating System": "Operating Systems",
    "Smart Card": "ICs, Smart Cards and Smart Card-Related Devices and Systems",
    "VPN": "Network and Network-Related Devices and Systems",
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


# Swedish scraping helpers


def _fetch_csec_pp_urls() -> list[str]:
    """Fetch the CSEC index page and return absolute URLs of individual PP subpages."""
    logger.info("Fetching CSEC PP index: %s", _CSEC_INDEX_URL)
    resp = requests.get(_CSEC_INDEX_URL, headers=_CSEC_HEADERS, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(resp.text, "html.parser")
    urls: list[str] = []
    for tag in soup.find_all("a", href=True):
        href: str = tag["href"]
        if not href.startswith("http"):
            href = _CSEC_BASE_URL + href
        # Keep only subpages of the index
        if href.startswith(_CSEC_INDEX_URL) and href.rstrip("/") != _CSEC_INDEX_URL.rstrip("/") and href not in urls:
            urls.append(href)
    logger.info("Found %d CSEC PP URLs.", len(urls))
    return urls


def _fetch_csec_pp_table(url: str) -> tuple[dict[str, Any], Any]:
    """Fetch a single CSEC PP page and return (table_dict, soup).

    table_dict maps the stripped text of the left column to the right <td> Tag.
    """
    from bs4 import BeautifulSoup, Tag

    resp = requests.get(url, headers=_CSEC_HEADERS, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    table: dict[str, Any] = {}
    tbl = soup.find("table")
    if tbl and isinstance(tbl, Tag):
        for row in tbl.find_all("tr"):
            cells = row.find_all(["th", "td"])
            if len(cells) >= 2:
                key = cells[0].get_text(strip=True)
                table[key] = cells[1]
    return table, soup


def _csec_get_name(table: dict[str, Any], soup: Any) -> str:
    """Extract PP name from CSEC table, falling back to the page <h1>."""
    for key in ("Skyddsprofilens namn", "Produktnamn"):
        cell = table.get(key)
        if cell is not None:
            return cell.get_text(strip=True)
    h1 = soup.find("h1")
    return h1.get_text(strip=True) if h1 else ""


def _csec_parse_security_level(raw: str) -> set[str]:
    """Parse 'EAL2 + ALC_FLR.1' into {'EAL2', 'ALC_FLR.1'}.

    Returns an empty set when the value cannot be interpreted as CC assurance components.
    """
    parts = {re.sub(r"^(EAL)\s+(\d)", r"\1\2", p.strip()) for p in raw.split("+")}
    return {p for p in parts if re.match(r"^EAL\d|^[A-Z]{2,}_[A-Z]{3}\.\d", p)}


def _csec_get_first_pdf_link(cell: Any, base_url: str) -> str | None:
    """Return the first PDF href found in *cell*, made absolute if needed."""
    if cell is None:
        return None
    for tag in cell.find_all("a", href=True):
        href: str = tag["href"]
        if ".pdf" in href.lower():
            if not href.startswith("http"):
                href = base_url + href
            return href
    return None


def _csec_table_to_scheme_entry(url: str, table: dict[str, Any], soup: Any) -> PPSchemeEntry:
    """Build a PPSchemeEntry from a parsed CSEC PP page."""
    name = _csec_get_name(table, soup)

    raw_eal = table.get("Assuranspaket")
    security_level = _csec_parse_security_level(raw_eal.get_text(strip=True)) if raw_eal is not None else set()

    date_cell = table.get("Certifieringsdatum")
    not_valid_before: date | None = None
    if date_cell is not None:
        with suppress(ValueError):
            not_valid_before = datetime.strptime(date_cell.get_text(strip=True), "%Y-%m-%d").date()

    report_link = _csec_get_first_pdf_link(table.get("Certifieringsrapport"), _CSEC_BASE_URL)
    pp_cell = table.get("Skyddsprofil, PP") or table.get("Produkts\u00e4kerhetsdeklaration, Security Target")
    pp_link = _csec_get_first_pdf_link(pp_cell, _CSEC_BASE_URL)

    cat_cell = table.get("Produktkategori")
    category = "Other Devices and Systems"
    if cat_cell is not None:
        category = _CSEC_PRODUKTKATEGORI_TO_CC_CATEGORY.get(cat_cell.get_text(strip=True), "Other Devices and Systems")

    return PPSchemeEntry(
        category=category,
        status="active",
        is_collaborative=False,
        name=name,
        version="",
        security_level=security_level,
        not_valid_before=not_valid_before,
        not_valid_after=None,
        report_link=report_link,
        pp_link=pp_link,
        scheme="SE",
        maintenances=[],
    )


class SwedishScraper:
    """Scraper for Swedish Protection Profiles from the FMV/CSEC portal."""

    scheme: str = "SE"

    def scrape(self) -> list[PPSchemeEntry]:
        """Fetch all certified Protection Profiles from the CSEC portal and return as PPSchemeEntry list."""
        try:
            urls = _fetch_csec_pp_urls()
        except Exception as e:
            logger.error("Failed to fetch CSEC PP index: %s", e)
            return []

        entries: list[PPSchemeEntry] = []
        for url in urls:
            try:
                table, soup = _fetch_csec_pp_table(url)
                entries.append(_csec_table_to_scheme_entry(url, table, soup))
            except Exception as e:
                logger.error("Error processing CSEC PP page %s: %s", url, e)

        logger.info("Parsed %d PPSchemeEntry objects from CSEC.", len(entries))
        return entries


# Korean ITSCC list page helpers


def _itscc_extract_csrf(soup: Any) -> str:
    """Extract the CSRF token from a hidden form input on an ITSCC page."""
    tag = soup.find("input", {"name": "csrf"})
    if tag is None:
        return ""
    return str(tag.get("value", ""))


def _itscc_parse_list_rows(soup: Any) -> list[dict[str, Any]]:
    """Parse the PP list table on an ITSCC list page.

    Table columns (0-indexed): name+link, KECS-PP-number, EAL, keyword, date.
    The product_id is embedded as id="w-XXXX" on the <a> in the first column.

    Returns a list of dicts with keys: pp_id (int), pp_number (str), eal (str), date_str (str).
    """
    from bs4 import Tag

    rows: list[dict[str, Any]] = []
    # The main data table is the second table on the page (index 1)
    tables = soup.find_all("table")
    if len(tables) < 2:
        return rows
    table = tables[1]
    if not isinstance(table, Tag):
        return rows
    for tr in table.find_all("tr"):
        cells = tr.find_all("td")
        # Expect 5 columns: name, KECS-PP-number, EAL, keyword, date
        if len(cells) < 5:
            continue
        # product_id from id="w-XXXX" on the <a> in the first cell
        link = cells[0].find("a", id=re.compile(r"^w-\d+$"))
        if not link:
            continue
        pp_id = int(str(link["id"]).lstrip("w-"))
        pp_number = cells[1].get_text(strip=True)
        rows.append(
            {
                "pp_id": pp_id,
                "pp_number": pp_number,
                "eal": cells[2].get_text(strip=True),
                "date_str": cells[4].get_text(strip=True),
            }
        )
    return rows


def _itscc_get_total_pages(soup: Any) -> int:
    """Extract the total number of pages from the ITSCC pagination div."""
    paginate = soup.find("div", class_="paginate")
    if not paginate:
        return 1
    page_links = paginate.find_all("a", class_=lambda c: c and "fnMove" in c)
    if not page_links:
        return 1
    return max(int(a.get("id", 1)) for a in page_links)


def _fetch_itscc_list_page(url: str, session: requests.Session, page_index: int) -> tuple[Any, str]:
    """Fetch the first page of the ITSCC PP list via GET. Returns (soup, csrf_token)."""
    from bs4 import BeautifulSoup

    resp = session.get(url, headers=_ITSCC_HEADERS, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    return soup, _itscc_extract_csrf(soup)


def _fetch_itscc_all_pp_ids(url: str, session: requests.Session, product_class: int) -> list[dict[str, Any]]:
    """Iterate all pages of an ITSCC PP list via POST pagination and return deduplicated row dicts."""
    from bs4 import BeautifulSoup

    # Page 1: GET to obtain CSRF token and total page count
    soup, csrf = _fetch_itscc_list_page(url, session, 1)
    total_pages = _itscc_get_total_pages(soup)

    all_rows: list[dict[str, Any]] = []
    seen_ids: set[int] = set()

    for page in range(1, total_pages + 1):
        if page == 1:
            page_soup = soup
        else:
            data = {
                "product_class": product_class,
                "selectPage": page,
                "csrf": csrf,
                "searchValueEn": "",
                "searchCertNo": "",
                "searchCertHolderEn": "",
                "searchYear": "",
            }
            resp = session.post(url, data=data, headers=_ITSCC_HEADERS, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            page_soup = BeautifulSoup(resp.text, "html.parser")

        for r in _itscc_parse_list_rows(page_soup):
            if r["pp_id"] not in seen_ids:
                seen_ids.add(r["pp_id"])
                all_rows.append(r)

    return all_rows


# Korean ITSCC detail page helpers


def _fetch_itscc_detail(
    session: requests.Session,
    product_id: int,
    product_class: int,
    csrf: str,
) -> Any:
    """POST to ITSCC view.do and return the parsed soup for the detail page."""
    from bs4 import BeautifulSoup

    payload = {
        "actType": "",
        "product_class": str(product_class),
        "product_id": str(product_id),
        "selectPage": "1",
        "orderBy": "",
        "csrf": csrf,
    }
    resp = session.post(_ITSCC_VIEW_URL, data=payload, headers=_ITSCC_HEADERS, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    return BeautifulSoup(resp.text, "html.parser")


def _itscc_abs_href(cell: Any) -> str | None:
    """Return the first absolute href found in *cell*, or None."""
    link = cell.find("a", href=True)
    if not link:
        return None
    href = str(link["href"])
    return _ITSCC_BASE_URL + href if not href.startswith("http") else href


def _itscc_apply_label(result: dict[str, Any], label: str, cell: Any) -> None:
    """Update *result* in-place based on the th label and corresponding td cell."""
    label_lower = label.lower()
    if "title" in label_lower:
        result["name"] = cell.get_text(strip=True)
    elif "assurance level" in label_lower:
        result["eal"] = cell.get_text(strip=True)
    elif "date of certification" in label_lower:
        with suppress(ValueError):
            result["date"] = datetime.strptime(cell.get_text(strip=True), "%Y-%m-%d").date()
    elif "type of pp" in label_lower:
        result["type_of_pp"] = cell.get_text(strip=True)
    elif "certification report" in label_lower and "no" not in label_lower:
        result["report_link"] = _itscc_abs_href(cell)
    elif "protection profile" in label_lower:
        result["pp_link"] = _itscc_abs_href(cell)


def _itscc_parse_detail(soup: Any) -> dict[str, Any]:
    """Extract fields from the ITSCC detail page (English).

    Returns a dict with keys: name, eal, date, type_of_pp, report_link, pp_link.
    The wideWidth table has a 4-column layout where each row can have two th/td pairs.
    """
    from bs4 import Tag

    result: dict[str, Any] = {
        "name": "",
        "eal": "",
        "date": None,
        "type_of_pp": "",
        "report_link": None,
        "pp_link": None,
    }

    tbl = soup.find("table", class_="wideWidth")
    if tbl is None or not isinstance(tbl, Tag):
        return result

    for tr in tbl.find_all("tr"):
        cells = tr.find_all(["th", "td"])
        i = 0
        while i + 1 < len(cells):
            if cells[i].name == "th":
                label = cells[i].get_text(separator=" ", strip=True)
                _itscc_apply_label(result, label, cells[i + 1])
                i += 2
            else:
                i += 1

    return result


# Korean ITSCC scraper


def _itscc_row_to_scheme_entry(detail: dict[str, Any], status: Literal["active", "archived"]) -> PPSchemeEntry:
    """Convert a parsed ITSCC detail dict into a PPSchemeEntry."""
    eal_raw = detail["eal"].strip()
    security_level: set[str] = {eal_raw} if re.match(r"^EAL\d", eal_raw) else set()
    category = _ITSCC_TYPE_TO_CC_CATEGORY.get(detail["type_of_pp"].strip(), "Other Devices and Systems")
    return PPSchemeEntry(
        category=category,
        status=status,
        is_collaborative=False,
        name=detail["name"],
        version="",
        security_level=security_level,
        not_valid_before=detail["date"],
        not_valid_after=None,
        report_link=detail["report_link"],
        pp_link=detail["pp_link"],
        scheme="KR",
        maintenances=[],
    )


class KoreanScraper:
    """Scraper for Korean Protection Profiles from the ITSCC portal (listA + listD)."""

    scheme: str = "KR"

    def scrape(self) -> list[PPSchemeEntry]:
        """Fetch all active and archived PPs from ITSCC and return as PPSchemeEntry list."""
        session = requests.Session()
        # Visit the English entry point so that subsequent requests return English content
        session.get(_ITSCC_BASE_URL + "/main/mainEn.do", headers=_ITSCC_HEADERS, timeout=REQUEST_TIMEOUT)
        entries: list[PPSchemeEntry] = []

        sources: list[tuple[str, int, Literal["active", "archived"]]] = [
            (_ITSCC_ACTIVE_LIST_URL, 1, "active"),
            (_ITSCC_ARCHIVED_LIST_URL, 4, "archived"),
        ]

        for list_url, product_class, status in sources:
            try:
                rows = _fetch_itscc_all_pp_ids(list_url, session, product_class)
            except Exception as e:
                logger.error("Failed to fetch ITSCC PP list %s: %s", list_url, e)
                continue

            # We need a fresh CSRF token for POST requests; grab it from the first list page
            try:
                _, csrf = _fetch_itscc_list_page(list_url, session, 1)
            except Exception as e:
                logger.error("Failed to fetch CSRF token from %s: %s", list_url, e)
                continue

            for row in rows:
                try:
                    detail_soup = _fetch_itscc_detail(session, row["pp_id"], product_class, csrf)
                    detail = _itscc_parse_detail(detail_soup)
                    entries.append(_itscc_row_to_scheme_entry(detail, status))
                except Exception as e:
                    logger.error("Error processing ITSCC PP %s: %s", row.get("pp_number", "?"), e)

        logger.info("Parsed %d PPSchemeEntry objects from ITSCC.", len(entries))
        return entries


PP_SCHEME_SCRAPERS: list[PPScraper] = [NIAPScraper(), SwedishScraper(), KoreanScraper()]
