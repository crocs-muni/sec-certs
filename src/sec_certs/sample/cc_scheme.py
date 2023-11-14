# This code is not a place of honor... no highly esteemed deed is commemorated here... nothing valued is here.
# What follows is a repulsive wall of BeautifulSoup garbage parsing code.
from __future__ import annotations

import hashlib
import math
import tempfile
import warnings
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urljoin

import requests
import tabula
from bs4 import BeautifulSoup, NavigableString, Tag
from requests import Response
from urllib3.connectionpool import InsecureRequestWarning

from sec_certs import constants
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils.sanitization import sanitize_navigable_string as sns
from sec_certs.utils.tqdm import tqdm

__all__ = [
    "get_australia_in_evaluation",
    "get_canada_certified",
    "get_canada_in_evaluation",
    "get_france_certified",
    "get_germany_certified",
    "get_india_certified",
    "get_india_archived",
    "get_italy_certified",
    "get_italy_in_evaluation",
    "get_japan_certified",
    "get_japan_archived",
    "get_japan_in_evaluation",
    "get_malaysia_certified",
    "get_malaysia_in_evaluation",
    "get_netherlands_certified",
    "get_netherlands_in_evaluation",
    "get_norway_certified",
    "get_norway_archived",
    "get_korea_certified",
    "get_korea_suspended",
    "get_korea_archived",
    "get_singapore_certified",
    "get_singapore_in_evaluation",
    "get_singapore_archived",
    "get_spain_certified",
    "get_sweden_certified",
    "get_sweden_in_evaluation",
    "get_sweden_archived",
    "get_turkey_certified",
    "get_usa_certified",
    "get_usa_in_evaluation",
    "get_usa_archived",
    "EntryType",
    "CCScheme",
]


def _get(url: str, session, **kwargs) -> Response:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=InsecureRequestWarning)
        conn = session if session else requests
        resp = conn.get(url, headers={"User-Agent": "seccerts.org"}, verify=False, **kwargs)
    resp.raise_for_status()
    return resp


def _get_page(url: str, session=None) -> BeautifulSoup:
    return BeautifulSoup(_get(url, session).content, "html5lib")


def _get_hash(url: str, session=None) -> bytes:
    resp = _get(url, session)
    h = hashlib.sha256()
    for chunk in resp.iter_content():
        h.update(chunk)
    return h.digest()


def get_australia_in_evaluation(enhanced: bool = True) -> list[dict[str, Any]]:  # noqa: C901
    """
    Get Australia "products in evaluation" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :return: The entries.
    """
    soup = _get_page(constants.CC_AUSTRALIA_INEVAL_URL)
    header = soup.find("h2", string="Products in evaluation")
    table = header.find_next_sibling("table")
    results = []
    for tr in tqdm(table.find_all("tr"), desc="Get AU scheme in evaluation."):
        tds = tr.find_all("td")
        if not tds:
            continue
        cert: dict[str, Any] = {
            "vendor": sns(tds[0].text),
            "product": sns(tds[1].text),
            "url": urljoin(constants.CC_AUSTRALIA_BASE_URL, tds[1].find("a")["href"]),
            "level": sns(tds[2].text),
        }
        if enhanced:
            e: dict[str, Any] = {}
            cert_page = _get_page(cert["url"])
            article = cert_page.find("article")
            blocks = article.find("div").find_all("div", class_="flex", recursive=False)
            for h2 in blocks[0].find_all("h2"):
                val = sns(h2.find_next_sibling("span").text)
                h_text = sns(h2.text)
                if not h_text:
                    continue
                if "Version:" in h_text:
                    e["version"] = val
                elif "Product type:" in h_text:
                    e["product_type"] = val
                elif "Product status:" in h_text:
                    e["product_status"] = val
                elif "Assurance level:" in h_text:
                    e["assurance_level"] = val
            sides = blocks[1].find_all("div", recursive=False)
            for div in sides[0].find_all("div", recursive=False):
                h2 = div.find("h2")
                h_text = sns(h2.text)
                if not h_text:
                    continue
                if "epl-vendor-token" in div.get("class"):
                    vendor_address = [h_text]
                    vendor_address.extend([sns(elem.text) for elem in h2.find_next_siblings("div")])  # type: ignore
                    e["vendor"] = "\n".join(vendor_address)
                else:
                    val = sns(h2.find_next_sibling("span").text)
                    if "Evaluation Facility:" in h_text:
                        e["evaluation_facility"] = val
                    elif "Certification Progress:" in h_text:
                        e["certification_progress"] = val
                    elif "Estimated Approval" in h_text:
                        e["estimated_approval"] = val
            e["contacts"] = [sns(p.text) for p in sides[1].find_all("p")]
            e["description"] = sns(blocks[2].find("span").text)
            cert["enhanced"] = e
        results.append(cert)
    return results


def get_canada_certified() -> list[dict[str, Any]]:
    """
    Get Canada "certified product" entries.

    :return: The entries.
    """
    resp = _get(constants.CC_CANADA_API_URL + f"?lang=en&url={constants.CC_CANADA_CERTIFIED_URL}", None)
    html_data = resp.json()["response"]["page"]["body"][0]
    soup = BeautifulSoup(html_data, "html5lib")
    tbody = soup.find("table").find("tbody")
    results = []
    for tr in tqdm(tbody.find_all("tr"), desc="Get CA scheme certified."):
        tds = tr.find_all("td")
        if not tds:
            continue
        cert = {
            "product": sns(tds[0].text),
            "vendor": sns(tds[1].text),
            "level": sns(tds[2].text),
            "certification_date": sns(tds[3].text),
        }
        results.append(cert)
    return results


def get_canada_in_evaluation() -> list[dict[str, Any]]:
    """
    Get Canada "products in evaluation" entries.

    :return: The entries.
    """
    resp = _get(constants.CC_CANADA_API_URL + f"?lang=en&url={constants.CC_CANADA_INEVAL_URL}", None)
    html_data = resp.json()["response"]["page"]["body"][0]
    soup = BeautifulSoup(html_data, "html5lib")
    tbody = soup.find("table").find("tbody")
    results = []
    for tr in tqdm(tbody.find_all("tr"), desc="Get CA scheme in evaluation."):
        tds = tr.find_all("td")
        if not tds:
            continue
        cert = {
            "product": sns(tds[0].text),
            "vendor": sns(tds[1].text),
            "level": sns(tds[2].text),
            "cert_lab": sns(tds[3].text),
        }
        results.append(cert)
    return results


def get_france_certified(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:  # noqa: C901
    """
    Get French "certified product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    base_soup = _get_page(constants.CC_ANSSI_CERTIFIED_URL)
    category_nav = base_soup.find("ul", class_="nav-categories")
    results = []
    for li in tqdm(category_nav.find_all("li"), desc="Get FR scheme certified."):
        a = li.find("a")
        url = a["href"]
        category_name = sns(a.text)
        soup = _get_page(urljoin(constants.CC_ANSSI_BASE_URL, url))
        table = soup.find("table", class_="produits-liste cc")
        if not table:
            continue
        tbody = table.find("tbody")
        for tr in tqdm(tbody.find_all("tr")):
            tds = tr.find_all("td")
            if not tds:
                continue
            cert: dict[str, Any] = {
                "product": sns(tds[0].text),
                "vendor": sns(tds[1].text),
                "level": sns(tds[2].text),
                "id": sns(tds[3].text),
                "certification_date": sns(tds[4].text),
                "category": category_name,
                "url": urljoin(constants.CC_ANSSI_BASE_URL, tds[0].find("a")["href"]),
            }
            if enhanced:
                e: dict[str, Any] = {}
                cert_page = _get_page(cert["url"])
                ref = cert_page.find("div", class_="ref-date")
                for ref_li in ref.find_all("li"):
                    title, value = (sns(span.text) for span in ref_li.find_all("span", recursive=False))
                    if not title:
                        continue
                    if "Référence" in title:
                        e["id"] = value
                    elif "Date de certification" in title:
                        e["certification_date"] = value
                    elif "Date de fin de validité" in title:
                        e["expiration_date"] = value
                details = cert_page.find("div", class_="details")
                for detail_li in details.find_all("li"):
                    title, value = (sns(span.text) for span in detail_li.find_all("span", recursive=False))
                    if not title:
                        continue
                    if "Catégorie" in title:
                        e["category"] = value
                    elif "Référentiel" in title:
                        e["cc_version"] = value
                    elif "Niveau" in title:
                        e["level"] = value
                    elif "Augmentations" in title:
                        e["augmentations"] = value
                    elif "Profil de protection" in title:
                        e["protection_profile"] = value
                    elif "Développeur" in title:
                        e["developer"] = value
                    elif "Centre d'évaluation" in title:
                        e["evaluation_facility"] = value
                    elif "Accords de reconnaissance" in title:
                        e["recognition"] = value
                e["description"] = sns(cert_page.find("div", class_="box-produit-descriptif").text)
                links = cert_page.find("div", class_="box-produit-telechargements")
                for link_li in links.find_all("li"):
                    a = link_li.find("a")
                    href = urljoin(constants.CC_ANSSI_BASE_URL, a["href"])
                    title = sns(a.text)
                    if not title:
                        continue
                    if "Rapport de certification" in title:
                        e["report_link"] = href
                        if artifacts:
                            e["report_hash"] = _get_hash(href).hex()
                    elif "Security target" in title:
                        e["target_link"] = href
                        if artifacts:
                            e["target_hash"] = _get_hash(href).hex()
                    elif "Certificat" in title:
                        e["cert_link"] = href
                        if artifacts:
                            e["cert_hash"] = _get_hash(href).hex()
                cert["enhanced"] = e
            results.append(cert)
    return results


def get_germany_certified(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:  # noqa: C901
    """
    Get German "certified product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    base_soup = _get_page(constants.CC_BSI_CERTIFIED_URL)
    category_nav = base_soup.find("ul", class_="no-bullet row")
    results = []
    for li in tqdm(category_nav.find_all("li"), desc="Get DE scheme certified."):
        a = li.find("a")
        url = a["href"]
        category_name = sns(a.text)
        soup = _get_page(urljoin(constants.CC_BSI_BASE_URL, url))
        content = soup.find("div", class_="content").find("div", class_="column")
        for table in tqdm(content.find_all("table")):
            tbody = table.find("tbody")
            header = table.find_parent("div", class_="wrapperTable").find_previous_sibling("h2")
            for tr in tqdm(tbody.find_all("tr")):
                tds = tr.find_all("td")
                if len(tds) != 4:
                    continue
                cert: dict[str, Any] = {
                    "cert_id": sns(tds[0].text),
                    "product": sns(tds[1].text),
                    "vendor": sns(tds[2].text),
                    "certification_date": sns(tds[3].text),
                    "category": category_name,
                    "url": urljoin(constants.CC_BSI_BASE_URL, tds[0].find("a")["href"]),
                }
                if enhanced:
                    e: dict[str, Any] = {}
                    cert_page = _get_page(cert["url"])
                    content = cert_page.find("div", id="content").find("div", class_="column")
                    head = content.find("h1", class_="c-intro__headline")
                    e["product"] = sns(head.next_sibling.text)
                    details = content.find("table")
                    for details_tr in details.find_all("tr"):
                        details_tds = details_tr.find_all("td")
                        title = sns(details_tds[0].find("span", attrs={"lang": "en-GB"}).text)
                        if not title:
                            continue
                        value = sns(details_tds[1].text)
                        if "Applicant" in title:
                            e["applicant"] = value
                        elif "Evaluation Facility" in title:
                            e["evaluation_facility"] = value
                        elif "Assurance" in title:
                            e["assurance_level"] = value
                        elif "Protection Profile" in title:
                            e["protection_profile"] = value
                        elif "Certification Date" in title:
                            e["certification_date"] = value
                        elif "valid until" in title:
                            e["expiration_date"] = value
                    links = content.find("ul")
                    if links:
                        # has multiple entries/recertifications
                        e["entries"] = []
                        for link_li in links.find_all("li"):
                            first_child = next(iter(link_li.children))
                            if isinstance(first_child, Tag):
                                link_id = sns(first_child.text)
                            elif isinstance(first_child, NavigableString):
                                link_id = sns(first_child.text).split(" ")[0]  # type: ignore
                            else:
                                link_id = None
                            entry = {"id": link_id}
                            en_spans = link_li.find_all("span", attrs={"lang": "en-GB"})
                            if en_spans:
                                entry["description"] = sns(en_spans[-1].text)
                            # TODO: Could parse the links to documents here
                            e["entries"].append(entry)
                    doc_links = content.find_all("a", title=lambda title: cert["cert_id"] in title)
                    for doc_link in doc_links:
                        href = urljoin(constants.CC_BSI_BASE_URL, doc_link["href"])
                        title = sns(doc_link["title"])
                        if not title:
                            continue
                        if "Certification Report" in title:
                            e["report_link"] = href
                            if artifacts:
                                e["report_hash"] = _get_hash(href).hex()
                        elif "Security Target" in title:
                            e["target_link"] = href
                            if artifacts:
                                e["target_hash"] = _get_hash(href).hex()
                        elif "Certificate" in title:
                            e["cert_link"] = href
                            if artifacts:
                                e["cert_hash"] = _get_hash(href).hex()
                    description = content.find("div", attrs={"lang": "en"})
                    if description:
                        e["description"] = sns(description.text)
                    cert["enhanced"] = e
                if header is not None:
                    cert["subcategory"] = sns(header.text)
                results.append(cert)
    return results


def _fix_india_link(link: str) -> str:
    return link.replace("/index.php", "")


def get_india_certified() -> list[dict[str, Any]]:
    """
    Get Indian "certified product" entries.

    :return: The entries.
    """
    pages = {0}
    seen_pages = set()
    results = []
    while pages:
        page = pages.pop()
        seen_pages.add(page)
        url = constants.CC_INDIA_CERTIFIED_URL + f"?page={page}"
        soup = _get_page(url)

        # Update pages
        pager = soup.find("ul", class_="pager__items")
        for li in pager.find_all("li"):
            try:
                new_page = int(li.text) - 1
            except Exception:
                continue
            if new_page not in seen_pages:
                pages.add(new_page)

        # Parse table
        tbody = soup.find("div", class_="view-content").find("table").find("tbody")
        for tr in tbody.find_all("tr"):
            tds = tr.find_all("td")
            if not tds:
                continue
            report_a = tds[6].find("a")
            target_a = tds[7].find("a")
            cert_a = tds[8].find("a")
            cert = {
                "serial_number": sns(tds[0].text),
                "product": sns(tds[1].text),
                "sponsor": sns(tds[2].text),
                "developer": sns(tds[3].text),
                "level": sns(tds[4].text),
                "issuance_date": sns(tds[5].text),
                "report_link": urljoin(constants.CC_INDIA_BASE_URL, _fix_india_link(report_a["href"])),
                "report_name": sns(report_a.text),
                "target_link": urljoin(constants.CC_INDIA_BASE_URL, _fix_india_link(target_a["href"])),
                "target_name": sns(target_a.text),
                "cert_link": urljoin(constants.CC_INDIA_BASE_URL, _fix_india_link(cert_a["href"])),
                "cert_name": sns(cert_a.text),
            }
            results.append(cert)
    return results


def get_india_archived() -> list[dict[str, Any]]:
    """
    Get Indian "archived product" entries.

    :return: The entries.
    """
    pages = {0}
    seen_pages = set()
    results = []
    while pages:
        page = pages.pop()
        seen_pages.add(page)
        url = constants.CC_INDIA_ARCHIVED_URL + f"?page={page}"
        soup = _get_page(url)

        # Update pages
        pager = soup.find("ul", class_="pager__items")
        if pager:
            for li in pager.find_all("li"):
                try:
                    new_page = int(li.text) - 1
                except Exception:
                    continue
                if new_page not in seen_pages:
                    pages.add(new_page)

        # Parse table
        tbody = soup.find("div", class_="view-content").find("table").find("tbody")
        for tr in tbody.find_all("tr"):
            tds = tr.find_all("td")
            if not tds:
                continue
            report_a = tds[5].find("a")
            target_a = tds[6].find("a")
            cert_a = tds[7].find("a")
            cert = {
                "serial_number": sns(tds[0].text),
                "product": sns(tds[1].text),
                "sponsor": sns(tds[2].text),
                "developer": sns(tds[3].text),
                "level": sns(tds[4].text),
                "target_link": urljoin(constants.CC_INDIA_BASE_URL, _fix_india_link(target_a["href"])),
                "target_name": sns(target_a.text),
                "cert_link": urljoin(constants.CC_INDIA_BASE_URL, _fix_india_link(cert_a["href"])),
                "cert_name": sns(cert_a.text),
                "certification_date": sns(tds[8].text),
            }
            if report_a:
                cert["report_link"] = urljoin(constants.CC_INDIA_BASE_URL, _fix_india_link(report_a["href"]))
                cert["report_name"] = sns(report_a.text)
            results.append(cert)
    return results


def get_italy_certified() -> list[dict[str, Any]]:  # noqa: C901
    """
    Get Italian "certified product" entries.

    :return: The entries.
    """
    soup = _get_page(constants.CC_ITALY_CERTIFIED_URL)
    div = soup.find("div", class_="certificati")
    results = []
    for cert_div in div.find_all("div", recursive=False):
        title = cert_div.find("h3").text
        data_div = cert_div.find("div", class_="collapse")
        cert = {"title": title}
        for data_p in data_div.find_all("p"):
            p_text = sns(data_p.text)
            if not p_text or ":" not in p_text:
                continue
            p_name, p_data = p_text.split(":")
            p_data = p_data
            p_link = data_p.find("a")
            if "Fornitore" in p_name:
                cert["supplier"] = p_data
            elif "Livello di garanzia" in p_name:
                cert["level"] = p_data
            elif "Data emissione certificato" in p_name:
                cert["certification_date"] = p_data
            elif "Data revisione" in p_name:
                cert["revision_date"] = p_data
            elif "Rapporto di Certificazione" in p_name and p_link:
                cert["report_link_it"] = urljoin(constants.CC_ITALY_BASE_URL, p_link["href"])
            elif "Certification Report" in p_name and p_link:
                cert["report_link_en"] = urljoin(constants.CC_ITALY_BASE_URL, p_link["href"])
            elif "Traguardo di Sicurezza" in p_name and p_link:
                cert["target_link"] = urljoin(constants.CC_ITALY_BASE_URL, p_link["href"])
            elif "Nota su" in p_name and p_link:
                cert["vulnerability_note_link"] = urljoin(constants.CC_ITALY_BASE_URL, p_link["href"])
            elif "Nota di chiarimento" in p_name and p_link:
                cert["clarification_note_link"] = urljoin(constants.CC_ITALY_BASE_URL, p_link["href"])
        results.append(cert)
    return results


def get_italy_in_evaluation() -> list[dict[str, Any]]:
    """
    Get Italian "product in evaluation" entries.

    :return: The entries.
    """
    soup = _get_page(constants.CC_ITALY_INEVAL_URL)
    div = soup.find("div", class_="valutazioni")
    results = []
    for cert_div in div.find_all("div", recursive=False):
        title = cert_div.find("h3").text
        data_div = cert_div.find("div", class_="collapse")
        cert = {"title": title}
        for data_p in data_div.find_all("p"):
            p_text = sns(data_p.text)
            if not p_text or ":" not in p_text:
                continue
            p_name, p_data = p_text.split(":")
            p_data = p_data
            if "Committente" in p_name:
                cert["client"] = p_data
            elif "Livello di garanzia" in p_name:
                cert["level"] = p_data
            elif "Tipologia prodotto" in p_name:
                cert["product_type"] = p_data
        results.append(cert)
    return results


def _get_japan(url, enhanced, artifacts) -> list[dict[str, Any]]:  # noqa: C901
    soup = _get_page(url)
    table = soup.find("table", class_="cert-table")
    results = []
    trs = list(table.find_all("tr"))
    for tr in trs:
        tds = tr.find_all("td")
        if not tds:
            continue
        if len(tds) == 6:
            cert: dict[str, Any] = {
                "cert_id": sns(tds[0].text),
                "supplier": sns(tds[1].text),
                "toe_overseas_name": sns(tds[2].text),
                "claim": sns(tds[4].text),
            }
            cert_date = sns(tds[3].text)
            toe_a = tds[2].find("a")
            if toe_a and "href" in toe_a.attrs:
                toe_link = urljoin(constants.CC_JAPAN_CERT_BASE_URL, toe_a["href"])
            else:
                toe_link = None
            if cert_date and "Assurance Continuity" in cert_date:
                cert["revalidations"] = [{"date": cert_date.split("(")[0], "link": toe_link}]
            else:
                cert["certification_date"] = cert_date
                cert["toe_overseas_link"] = toe_link
            results.append(cert)
        if len(tds) == 1:
            cert = results[-1]
            cert["toe_japan_name"] = sns(tds[0].text)
            toe_a = tds[0].find("a")
            if toe_a and "href" in toe_a.attrs:
                cert["toe_japan_link"] = urljoin(constants.CC_JAPAN_CERT_BASE_URL, toe_a["href"])
        if len(tds) == 2:
            cert = results[-1]
            cert["certification_date"] = sns(tds[1].text)
            toe_a = tds[0].find("a")
            if toe_a and "href" in toe_a.attrs:
                toe_link = urljoin(constants.CC_JAPAN_CERT_BASE_URL, toe_a["href"])
            else:
                toe_link = None
            cert["toe_overseas_link"] = toe_link
    if enhanced:
        for cert in results:
            e: dict[str, Any] = {}
            cert_link = cert.get("toe_overseas_link") or cert.get("toe_japan_link")
            if not cert_link:
                continue
            cert_page = _get_page(cert_link)
            main = cert_page.find("div", id="main")
            left = main.find("div", id="left")
            for dl in left.find_all("dl"):
                dt = dl.find("dt")
                title = sns(dt.text)
                value = sns(dt.find_next_sibling().text)
                if not title:
                    continue
                if "Product Name" in title:
                    e["product"] = value
                elif "Version of TOE" in title:
                    e["toe_version"] = value
                elif "Product Type" in title:
                    e["product_type"] = value
                elif "Certification Identification" in title:
                    e["cert_id"] = value
                elif "Version of Common Criteria" in title:
                    e["cc_version"] = value
                elif "Date" in title:
                    e["certification_date"] = value
                elif "Conformance Claim" in title:
                    e["assurance_level"] = value
                elif "PP Identifier" in title and value != "None":
                    e["protection_profile"] = value
            right = main.find("div", id="right")
            for dl in right.find_all("dl", recursive=False):
                title = sns(dl.find("dt").text)
                value = sns(dl.find("dd").text)
                if not title:
                    continue
                if "Vendor" in title:
                    e["vendor"] = value
                elif "Evaluation Facility" in title:
                    e["evaluation_facility"] = value
            pdfbox = main.find("div", id="pdfbox")
            if pdfbox:
                for li in pdfbox.find_all("li"):
                    li_a = li.find("a")
                    name = sns(li_a.text)
                    if not name:
                        continue
                    if "Report" in name:
                        e["report_link"] = urljoin(constants.CC_JAPAN_BASE_URL, li_a["href"])
                        if artifacts:
                            e["report_hash"] = _get_hash(e["report_link"]).hex()
                    elif "Certificate" in name:
                        e["cert_link"] = urljoin(constants.CC_JAPAN_BASE_URL, li_a["href"])
                        if artifacts:
                            e["cert_hash"] = _get_hash(e["cert_link"]).hex()
                    elif "Target" in name:
                        e["target_link"] = urljoin(constants.CC_JAPAN_BASE_URL, li_a["href"])
                        if artifacts:
                            e["target_hash"] = _get_hash(e["target_link"]).hex()
            e["description"] = sns(main.find("div", id="overviewsbox").text)
            cert["enhanced"] = e
    return results


def get_japan_certified(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Japanese "certified product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    japan_hw = _get_japan(constants.CC_JAPAN_CERTIFIED_HW_URL, enhanced, artifacts)
    japan_sw = _get_japan(constants.CC_JAPAN_CERTIFIED_SW_URL, enhanced, artifacts)
    return japan_sw + japan_hw


def get_japan_archived(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Japanese "archived product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_japan(constants.CC_JAPAN_ARCHIVED_SW_URL, enhanced, artifacts)


def get_japan_in_evaluation() -> list[dict[str, Any]]:
    """
    Get Japanese "product in evaluation" entries.

    :return: The entries.
    """
    soup = _get_page(constants.CC_JAPAN_INEVAL_URL)
    table = soup.find("table")
    results = []
    for tr in table.find_all("tr"):
        tds = tr.find_all("td")
        if not tds:
            continue
        toe_a = tds[1].find("a")
        cert = {
            "supplier": sns(tds[0].text),
            "toe_name": sns(toe_a.text),
            "toe_link": urljoin(constants.CC_JAPAN_BASE_URL, toe_a["href"]),
            "claim": sns(tds[2].text),
        }
        results.append(cert)
    return results


def get_malaysia_certified() -> list[dict[str, Any]]:
    """
    Get Malaysian "certified product" entries.

    :return: The entries.
    """
    soup = _get_page(constants.CC_MALAYSIA_CERTIFIED_URL)
    sections = soup.find("div", attrs={"itemprop": "articleBody"}).find_all("section", class_="sppb-section")
    results = []
    for section in sections:
        table = section.find("table")
        if table is None:
            continue
        heading = section.find("h5")
        if heading is None:
            continue
        category_name = sns(heading.text)
        tbody = table.find("tbody")
        for tr in tbody.find_all("tr", recursive=False):
            tds = tr.find_all("td", recursive=False)
            if len(tds) != 6:
                continue
            cert = {
                "category": category_name,
                "level": sns(tds[0].text),
                "cert_id": sns(tds[1].text),
                "certification_date": sns(tds[2].text),
                "product": sns(tds[3].text),
                "developer": sns(tds[4].text),
            }
            results.append(cert)
    return results


def get_malaysia_in_evaluation() -> list[dict[str, Any]]:
    """
    Get Malaysian "product in evaluation" entries.

    :return: The entries.
    """
    soup = _get_page(constants.CC_MALAYSIA_INEVAL_URL)
    main_div = soup.find("div", attrs={"itemprop": "articleBody"})
    table = main_div.find("table")
    results = []
    for tr in table.find_all("tr")[1:]:
        tds = tr.find_all("td")
        if len(tds) != 5:
            continue
        cert = {
            "level": sns(tds[0].text),
            "project_id": sns(tds[1].text),
            "toe_name": sns(tds[2].text),
            "developer": sns(tds[3].text),
            "expected_completion": sns(tds[4].text),
        }
        results.append(cert)
    return results


def get_netherlands_certified(artifacts: bool = False) -> list[dict[str, Any]]:  # noqa: C901
    """
    Get Dutch "certified product" entries.

    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    soup = _get_page(constants.CC_NETHERLANDS_CERTIFIED_URL)
    main_div = soup.select("body > main > div > div > div > div:nth-child(2) > div.col-lg-9 > div:nth-child(3)")[0]
    rows = main_div.find_all("div", class_="row", recursive=False)
    modals = main_div.find_all("div", class_="modal", recursive=False)
    results = []
    for row, modal in zip(rows, modals):
        row_entries = row.find_all("a")
        modal_trs = modal.find_all("tr")
        cert: dict[str, Any] = {
            "manufacturer": sns(row_entries[0].text),
            "product": sns(row_entries[1].text),
            "scheme": sns(row_entries[2].text),
            "cert_id": sns(row_entries[3].text),
        }
        for tr in modal_trs:
            th_text = tr.find("th").text
            td = tr.find("td")
            if "Manufacturer website" in th_text:
                cert["manufacturer_link"] = td.find("a")["href"]
            elif "Assurancelevel" in th_text:
                cert["level"] = sns(td.text)
            elif "Certificate" in th_text:
                cert["cert_link"] = urljoin(constants.CC_NETHERLANDS_BASE_URL, td.find("a")["href"])
                if artifacts:
                    cert["cert_hash"] = _get_hash(cert["cert_link"]).hex()
            elif "Certificationreport" in th_text:
                cert["report_link"] = urljoin(constants.CC_NETHERLANDS_BASE_URL, td.find("a")["href"])
                if artifacts:
                    cert["report_hash"] = _get_hash(cert["report_link"]).hex()
            elif "Securitytarget" in th_text:
                cert["target_link"] = urljoin(constants.CC_NETHERLANDS_BASE_URL, td.find("a")["href"])
                if artifacts:
                    cert["target_hash"] = _get_hash(cert["target_link"]).hex()
            elif "Maintenance report" in th_text:
                cert["maintenance_link"] = urljoin(constants.CC_NETHERLANDS_BASE_URL, td.find("a")["href"])
                if artifacts:
                    cert["maintenance_hash"] = _get_hash(cert["maintenance_link"]).hex()
        results.append(cert)
    return results


def get_netherlands_in_evaluation() -> list[dict[str, Any]]:
    """
    Get Dutch "product in evaluation" entries.

    :return: The entries.
    """
    soup = _get_page(constants.CC_NETHERLANDS_INEVAL_URL)
    table = soup.find("table")
    results = []
    for tr in table.find_all("tr")[1:]:
        tds = tr.find_all("td")
        cert = {
            "developer": sns(tds[0].text),
            "product": sns(tds[1].text),
            "category": sns(tds[2].text),
            "level": sns(tds[3].text),
            "certification_id": sns(tds[4].text),
        }
        results.append(cert)
    return results


def _get_norway(url: str, enhanced: bool, artifacts: bool) -> list[dict[str, Any]]:  # noqa: C901
    soup = _get_page(url)
    results = []
    for tr in soup.find_all("tr", class_="certified-product"):
        tds = tr.find_all("td")
        cert: dict[str, Any] = {
            "product": sns(tds[0].text),
            "url": tds[0].find("a")["href"],
            "category": sns(tds[1].find("p", class_="value").text),
            "developer": sns(tds[2].find("p", class_="value").text),
            "certification_date": sns(tds[3].find("time").text),
        }
        if enhanced:
            e: dict[str, Any] = {}
            cert_page = _get_page(cert["url"])
            content = cert_page.find("div", class_="main-content")
            body = content.find("div", class_="articleelement")
            if body:
                e["description"] = sns(body.text)
            specs = content.find("div", class_="specifications")
            for row in specs.find_all("div", class_="row"):
                title = sns(row.find("div", class_="label").text)
                value = sns(row.find("div", class_="value").text)
                if not title:
                    continue
                if "Certificate No." in title and value is not None:
                    e["id"] = value.split(" ")[0]
                elif "Mutual Recognition" in title:
                    e["mutual_recognition"] = value
                elif "Product" in title:
                    e["product"] = value
                elif "Category" in title:
                    e["category"] = value
                elif "Sponsor" in title:
                    e["sponsor"] = value
                elif "Developer" in title:
                    e["developer"] = value
                elif "Evaluation Facility" in title:
                    e["evaluation_facility"] = value
                elif "Certification Date" in title:
                    e["certification_date"] = value
                elif "Evaluation Level" in title:
                    e["level"] = value
                elif "Protection Profile" in title:
                    e["protection_profile"] = value
            docs = content.find("div", class_="documents").find("div", class_="card-body")
            e["documents"] = {}
            for doc_collection in docs.find_all("div", class_="document-collection"):
                head = sns(doc_collection.find("div", class_="header").text)
                links = doc_collection.find_all("li")
                if not head:
                    continue
                if "Certificates" in head:
                    doc_type = "cert"
                elif "Security targets" in head:
                    doc_type = "target"
                elif "Certification reports" in head:
                    doc_type = "report"
                elif "Maintenance report" in head:
                    doc_type = "maintenance"
                else:
                    continue
                entries = []
                for link in links:
                    a = link.find("a")
                    entry = {"href": urljoin(constants.CC_NORWAY_BASE_URL, a["href"])}
                    if artifacts:
                        entry["hash"] = _get_hash(entry["href"]).hex()
                    entries.append(entry)
                e["documents"][doc_type] = entries
            cert["enhanced"] = e
        results.append(cert)
    return results


def get_norway_certified(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Norwegian "certified product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_norway(constants.CC_NORWAY_CERTIFIED_URL, enhanced, artifacts)


def get_norway_archived(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Norwegian "archived product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_norway(constants.CC_NORWAY_ARCHIVED_URL, enhanced, artifacts)


def _get_korea(product_class: int, enhanced: bool, artifacts: bool) -> list[dict[str, Any]]:  # noqa: C901
    session = requests.session()
    session.get(constants.CC_KOREA_EN_URL)
    # Get base page
    url = constants.CC_KOREA_CERTIFIED_URL + f"?product_class={product_class}"
    soup = _get_page(url, session=session)
    seen_pages = set()
    pages = {1}
    results = []
    while pages:
        page = pages.pop()
        csrf = soup.find("form", id="fm").find("input", attrs={"name": "csrf"})["value"]
        resp = session.post(url, data={"csrf": csrf, "selectPage": page, "product_class": product_class})
        soup = BeautifulSoup(resp.content, "html5lib")
        tbody = soup.find("table", class_="cpl").find("tbody")
        for tr in tbody.find_all("tr"):
            tds = tr.find_all("td")
            if len(tds) != 6:
                continue
            link = tds[0].find("a")
            id = link["id"].split("-")[1]
            cert: dict[str, Any] = {
                "product": sns(tds[0].text),
                "cert_id": sns(tds[1].text),
                "product_link": constants.CC_KOREA_PRODUCT_URL.format(id),
                "vendor": sns(tds[2].text),
                "level": sns(tds[3].text),
                "category": sns(tds[4].text),
                "certification_date": sns(tds[5].text),
            }
            if enhanced:
                e: dict[str, Any] = {}
                if not cert["product_link"]:
                    continue
                cert_page = _get_page(cert["product_link"], session)
                main = cert_page.find("div", class_="mainContent")
                table = main.find("table", class_="shortenedWidth")
                v = e
                for tr in table.find_all("tr"):
                    th = tr.find("th")
                    td = tr.find("td")
                    if not th:
                        mus = e.setdefault("maintenance_update", [])
                        v = {"name": sns(td.text)}
                        mus.append(v)
                        continue
                    title = sns(th.text)
                    value = sns(td.text)
                    a = td.find("a")
                    if not title:
                        continue
                    if "Product Name" in title:
                        v["product"] = value
                    elif "Common Criteria" in title:
                        v["cc_version"] = value
                    elif "Date of Certification" in title or "Date issued" in title:
                        v["certification_date"] = value
                    elif "EvaluationAssurance Level" in title:
                        v["assurance_level"] = value
                    elif "Expiry Date" in title:
                        v["expiration_date"] = value
                    elif "Type of Product" in title:
                        v["product_type"] = value
                    elif "Certification No." in title:
                        v["cert_id"] = value
                    elif "Protection Profile" in title:
                        v["protection_profile"] = value
                    elif "Developer" in title:
                        v["developer"] = value
                    elif "Certificate Holder" in title:
                        v["holder"] = value
                    elif "Certificate" in title and a:
                        v["cert_link"] = urljoin(constants.CC_KOREA_BASE_URL, a["href"])
                        if artifacts:
                            v["cert_hash"] = _get_hash(v["cert_link"], session).hex()
                    elif "Security Target" in title and a:
                        v["target_link"] = urljoin(constants.CC_KOREA_BASE_URL, a["href"])
                        if artifacts:
                            v["target_hash"] = _get_hash(v["target_link"], session).hex()
                    elif "Certification Report" in title and a:
                        v["report_link"] = urljoin(constants.CC_KOREA_BASE_URL, a["href"])
                        if artifacts:
                            v["report_hash"] = _get_hash(v["report_link"], session).hex()
                    elif "Maintenance Report" in title and a:
                        v["maintenance_link"] = urljoin(constants.CC_KOREA_BASE_URL, a["href"])
                        if artifacts:
                            v["maintenance_hash"] = _get_hash(v["maintenance_link"], session).hex()
                cert["enhanced"] = e
            results.append(cert)
        seen_pages.add(page)
        page_links = soup.find("div", class_="paginate").find_all("a", class_="number_off")
        for page_link in page_links:
            try:
                new_page = int(page_link.text)
                if new_page not in seen_pages:
                    pages.add(new_page)
            except Exception:
                pass
    return results


def get_korea_certified(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Korean "certified product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_korea(product_class=1, enhanced=enhanced, artifacts=artifacts)


def get_korea_suspended(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Korean "suspended product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_korea(product_class=2, enhanced=enhanced, artifacts=artifacts)


def get_korea_archived(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Korean "product in evaluation" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_korea(product_class=4, enhanced=enhanced, artifacts=artifacts)


def _get_singapore(url: str, artifacts: bool) -> list[dict[str, Any]]:
    soup = _get_page(url)
    page_id = str(soup.find("input", id="CurrentPageId").value)
    page = 1
    api_call = requests.post(
        constants.CC_SINGAPORE_API_URL,
        data={
            "PassSortFilter": False,
            "currentPageId": page_id,
            "page": page,
            "limit": 15,
            "ProductDeveloperName": "",
        },
    )
    api_json = api_call.json()
    total = api_json["total"]
    results: list[dict[str, Any]] = []
    while len(results) != total:
        for obj in api_json["objects"]:
            cert: dict[str, Any] = {
                "level": obj["assuranceLevel"],
                "product": obj["productName"],
                "vendor": obj["productDeveloper"],
                "url": urljoin(constants.CC_SINGAPORE_BASE_URL, obj["productUrl"]),
                "certification_date": obj["dateOfIssuance"],
                "expiration_date": obj["dateOfExpiry"],
                "category": obj["productCategory"]["title"],
                "cert_title": obj["certificate"]["title"],
                "cert_link": urljoin(constants.CC_SINGAPORE_BASE_URL, obj["certificate"]["mediaUrl"]),
                "report_title": obj["certificationReport"]["title"],
                "report_link": urljoin(constants.CC_SINGAPORE_BASE_URL, obj["certificationReport"]["mediaUrl"]),
                "target_title": obj["securityTarget"]["title"],
                "target_link": urljoin(constants.CC_SINGAPORE_BASE_URL, obj["securityTarget"]["mediaUrl"]),
            }
            if artifacts:
                cert["cert_hash"] = _get_hash(cert["cert_link"]).hex()
                cert["report_hash"] = _get_hash(cert["report_link"]).hex()
                cert["target_hash"] = _get_hash(cert["target_link"]).hex()
            results.append(cert)
        page += 1
        api_call = requests.post(
            constants.CC_SINGAPORE_API_URL,
            data={
                "PassSortFilter": False,
                "currentPageId": page_id,
                "page": page,
                "limit": 15,
                "ProductDeveloperName": "",
            },
        )
        api_json = api_call.json()
    return results


def get_singapore_certified(artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Singaporean "certified product" entries.

    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_singapore(constants.CC_SINGAPORE_CERTIFIED_URL, artifacts)


def get_singapore_in_evaluation() -> list[dict[str, Any]]:
    """
    Get Singaporean "product in evaluation" entries.

    :return: The entries.
    """
    soup = _get_page(constants.CC_SINGAPORE_INEVAL_URL)
    blocks = soup.find_all("div", class_="sfContentBlock")
    for block in blocks:
        table = block.find("table")
        if table:
            break
    else:
        raise ValueError("Cannot find table.")
    results = []
    for tr in table.find_all("tr")[1:]:
        tds = tr.find_all("td")
        cert = {
            "name": sns(tds[0].text),
            "vendor": sns(tds[1].text),
            "level": sns(tds[2].text),
        }
        results.append(cert)
    return results


def get_singapore_archived(artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Singaporean "archived product" entries.

    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_singapore(constants.CC_SINGAPORE_ARCHIVED_URL, artifacts)


def get_spain_certified() -> list[dict[str, Any]]:
    """
    Get Spanish "certified product" entries.

    :return: The entries.
    """
    soup = _get_page(constants.CC_SPAIN_CERTIFIED_URL)
    tbody = soup.find("table", class_="djc_items_table").find("tbody")
    results = []
    for tr in tbody.find_all("tr", recursive=False):
        tds = tr.find_all("td")
        cert = {
            "product": sns(tds[0].text),
            "product_link": urljoin(constants.CC_SPAIN_BASE_URL, tds[0].find("a")["href"]),
            "category": sns(tds[1].text),
            "manufacturer": sns(tds[2].text),
            "certification_date": sns(tds[3].find("td", class_="djc_value").text),
        }
        results.append(cert)
    return results


def _get_sweden(url: str, enhanced: bool, artifacts: bool) -> list[dict[str, Any]]:  # noqa: C901
    soup = _get_page(url)
    nav = soup.find("main").find("nav", class_="component-nav-box__list")
    results = []
    for link in nav.find_all("a"):
        cert: dict[str, Any] = {
            "product": sns(link.text),
            "url": urljoin(constants.CC_SWEDEN_BASE_URL, link["href"]),
        }
        if enhanced:
            e: dict[str, Any] = {}
            if not cert["url"]:
                continue
            cert_page = _get_page(cert["url"])
            content = cert_page.find("section", class_="container-article")
            head = content.find("h1")
            e["title"] = sns(head.text)
            table = content.find("table")
            if table:
                for tr in table.find_all("tr"):
                    tds = tr.find_all("td")
                    if len(tds) != 2:
                        continue
                    title = sns(tds[0].text)
                    value = sns(tds[1].text)
                    a = tds[1].find("a")
                    if not title:
                        continue
                    if "Certifierings ID" in title:
                        e["cert_id"] = value
                    elif "Giltighet" in title:
                        e["mutual_recognition"] = value
                    elif "Produktnamn" in title:
                        e["product"] = value
                    elif "Produktkategori" in title:
                        e["category"] = value
                    elif "Assuranspaket" in title:
                        e["assurance_level"] = value
                    elif "Certifieringsdatum" in title:
                        e["certification_date"] = value
                    elif "Sponsor" in title:
                        e["sponsor"] = value
                    elif "Utvecklare" in title:
                        e["developer"] = value
                    elif "Evalueringsföretag" in title:
                        e["evaluation_facility"] = value
                    elif "Security Target" in title and a:
                        e["target_link"] = urljoin(constants.CC_SWEDEN_BASE_URL, a["href"])
                        if artifacts:
                            e["target_hash"] = _get_hash(e["target_link"]).hex()
                    elif "Certifieringsrapport" in title and a:
                        e["report_link"] = urljoin(constants.CC_SWEDEN_BASE_URL, a["href"])
                        if artifacts:
                            e["report_hash"] = _get_hash(e["report_hash"]).hex()
                    elif "Certifikat" in title and a:
                        e["cert_link"] = urljoin(constants.CC_SWEDEN_BASE_URL, a["href"])
                        if artifacts:
                            e["cert_hash"] = _get_hash(e["cert_link"]).hex()
            cert["enhanced"] = e
        results.append(cert)
    return results


def get_sweden_certified(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Swedish "certified product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_sweden(constants.CC_SWEDEN_CERTIFIED_URL, enhanced, artifacts)


def get_sweden_in_evaluation(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Swedish "product in evaluation" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_sweden(constants.CC_SWEDEN_INEVAL_URL, enhanced, artifacts)


def get_sweden_archived(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Swedish "archived product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_sweden(constants.CC_SWEDEN_ARCHIVED_URL, enhanced, artifacts)


def get_turkey_certified() -> list[dict[str, Any]]:
    """
    Get Turkish "certified product" entries.

    :return: The entries.
    """
    results = []
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "turkey.pdf"
        resp = requests.get(constants.CC_TURKEY_ARCHIVED_URL)
        if resp.status_code != requests.codes.ok:
            raise ValueError(f"Unable to download: status={resp.status_code}")
        with pdf_path.open("wb") as f:
            f.write(resp.content)
        dfs = tabula.read_pdf(str(pdf_path), pages="all")
        for df in dfs:
            for line in df.values:  # type: ignore
                values = [value if not (isinstance(value, float) and math.isnan(value)) else None for value in line]
                cert = {
                    # TODO: Split item number and generate several dicts for a range they include.
                    "item_no": values[0],
                    "developer": values[1],
                    "product": values[2],
                    "cc_version": values[3],
                    "level": values[4],
                    "cert_lab": values[5],
                    "certification_date": values[6],
                    "expiration_date": values[7],
                    # TODO: Parse "Ongoing Evaluation" out of this field as well.
                    "archived": isinstance(values[9], str) and "Archived" in values[9],
                }
                results.append(cert)
    return results


def get_usa_certified(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:  # noqa: C901
    """
    Get American "certified product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    # TODO: Information could be expanded by following the cc_claims (has links to protection profiles).
    soup = _get_page(constants.CC_USA_CERTIFIED_URL)
    tbody = soup.find("table", class_="tablesorter").find("tbody")
    results = []
    for tr in tbody.find_all("tr"):
        tds = tr.find_all("td")
        vendor_span = tds[0].find("span", class_="b u")
        product_link = tds[0].find("a")
        scheme_img = tds[6].find("img")
        # Only return the US certifications.
        if scheme_img["title"] != "USA":
            continue
        cert: dict[str, Any] = {
            "product": sns(product_link.text),
            "vendor": sns(vendor_span.text),
            "product_link": urljoin(constants.CC_USA_PRODUCT_URL, product_link["href"]),
            "id": sns(tds[1].text),
            "cc_claim": sns(tds[2].text),
            "cert_lab": sns(tds[3].text),
            "certification_date": sns(tds[4].text),
            "assurance_maintenance_date": sns(tds[5].text),
        }
        if enhanced:
            e: dict[str, Any] = {}
            if not cert["product_link"]:
                continue
            cert_page = _get_page(cert["product_link"])
            details = cert_page.find("div", class_="txt2 lma")
            for span in details.find_all("span"):
                title = sns(span.text)
                if not title:
                    continue
                sibling = span.next_sibling
                value = sns(sibling.text)
                if "Certificate Date" in title:
                    e["certification_date"] = value
                elif "Product Type" in title:
                    e["product_type"] = value
                elif "Conformance Claim" in title:
                    e["cc_claim"] = value
                elif "Validation Report Number" in title:
                    e["cert_id"] = value
                elif "PP Identifier" in title:
                    e["protection_profile"] = sns(span.find_next_sibling("a").text)
                elif "CC Testing Lab" in title:
                    e["evaluation_facility"] = sns(span.find_next_sibling("a").text)
            links = cert_page.find_all("a", class_="pseudobtn1")
            for link in links:
                name = sns(link.text)
                href = urljoin(constants.CC_USA_BASE_URL, sns(link["href"]))
                if not name:
                    continue
                if "CC Certificate" in name:
                    e["cert_link"] = href
                    if artifacts:
                        e["cert_hash"] = _get_hash(href).hex()
                elif "Security Target" in name:
                    e["target_link"] = href
                    if artifacts:
                        e["target_hash"] = _get_hash(href).hex()
                elif "Validation Report" in name:
                    e["report_link"] = href
                    if artifacts:
                        e["report_hash"] = _get_hash(href).hex()
                elif "Assurance Activity" in name:
                    e["assurance_activity_link"] = href
                    if artifacts:
                        e["assurance_activity_hash"] = _get_hash(href).hex()
                elif "Administrative Guide" in name:
                    guides = e.setdefault("administrative_guides", [])
                    guide = {"link": href}
                    guides.append(guide)
                    if artifacts:
                        guide["hash"] = _get_hash(href).hex()
            cert["enhanced"] = e
        results.append(cert)
    return results


def get_usa_in_evaluation() -> list[dict[str, Any]]:
    """
    Get American "product in evaluation" entries.

    :return: The entries.
    """
    # TODO: Information could be expanded by following the cc_claims (has links to protection profiles).
    soup = _get_page(constants.CC_USA_INEVAL_URL)
    tbody = soup.find("table", class_="tablesorter").find("tbody")
    results = []
    for tr in tbody.find_all("tr"):
        tds = tr.find_all("td")
        vendor_span = tds[0].find("span", class_="b u")
        product_name = None
        for child in tds[0].children:
            if isinstance(child, NavigableString):
                product_name = sns(child)
                break
        cert = {
            "vendor": sns(vendor_span.text),
            "id": sns(tds[1].text),
            "cc_claim": sns(tds[2].text),
            "cert_lab": sns(tds[3].text),
            "kickoff_date": sns(tds[4].text),
        }
        if product_name:
            cert["product"] = product_name
        results.append(cert)
    return results


def get_usa_archived() -> list[dict[str, Any]]:
    """
    Get American "archived product" entries.

    :return: The entries.
    """
    # TODO: Information could be expanded by following the cc_claims (has links to protection profiles).
    soup = _get_page(constants.CC_USA_ARCHIVED_URL)
    tbody = soup.find("table", class_="tablesorter").find("tbody")
    results = []
    for tr in tbody.find_all("tr"):
        tds = tr.find_all("td")
        scheme_img = tds[5].find("img")
        # Only return the US certifications.
        if scheme_img["title"] != "USA":
            continue
        vendor_span = tds[0].find("span", class_="b u")
        product_name = None
        for child in tds[0].children:
            if isinstance(child, NavigableString):
                product_name = sns(child)
                break
        cert = {
            "vendor": sns(vendor_span.text),
            "id": sns(tds[1].text),
            "cc_claim": sns(tds[2].text),
            "cert_lab": sns(tds[3].text),
            "certification_date": sns(tds[4].text),
        }
        if product_name:
            cert["product"] = product_name
        results.append(cert)
    return results


class EntryType(Enum):
    Certified = "CERTIFIED"
    InEvaluation = "INEVALUATION"
    Archived = "ARCHIVED"


@dataclass
class CCScheme(ComplexSerializableType):
    """
    Dataclass for data extracted from a CCScheme website, so more like a
    "CCSchemeWebDump" but that classname is not so nice.

    Contains the country (scheme) code a timestamp of extraction and
    several lists of entries: certified, in-evaluation and archived.
    It may only contain some lists of entries as the scheme might only publish
    them.
    """

    country: str
    timestamp: datetime
    lists: dict[EntryType, Any]

    methods: ClassVar[dict[str, dict[EntryType, Callable]]] = {
        "AU": {EntryType.InEvaluation: get_australia_in_evaluation},
        "CA": {EntryType.InEvaluation: get_canada_in_evaluation, EntryType.Certified: get_canada_certified},
        "FR": {EntryType.Certified: get_france_certified},
        "DE": {EntryType.Certified: get_germany_certified},
        "IN": {EntryType.Certified: get_india_certified, EntryType.Archived: get_india_archived},
        "IT": {EntryType.Certified: get_italy_certified, EntryType.InEvaluation: get_italy_in_evaluation},
        "JP": {
            EntryType.InEvaluation: get_japan_in_evaluation,
            EntryType.Certified: get_japan_certified,
            EntryType.Archived: get_japan_archived,
        },
        "MY": {EntryType.Certified: get_malaysia_certified, EntryType.InEvaluation: get_malaysia_in_evaluation},
        "NL": {EntryType.Certified: get_netherlands_certified, EntryType.InEvaluation: get_netherlands_in_evaluation},
        "NO": {EntryType.Certified: get_norway_certified, EntryType.Archived: get_norway_archived},
        "KO": {EntryType.Certified: get_korea_certified, EntryType.Archived: get_korea_archived},
        "SG": {
            EntryType.InEvaluation: get_singapore_in_evaluation,
            EntryType.Certified: get_singapore_certified,
            EntryType.Archived: get_singapore_archived,
        },
        "ES": {EntryType.Certified: get_spain_certified},
        "SE": {
            EntryType.InEvaluation: get_sweden_in_evaluation,
            EntryType.Certified: get_sweden_certified,
            EntryType.Archived: get_sweden_archived,
        },
        "TR": {EntryType.Certified: get_turkey_certified},
        "US": {
            EntryType.InEvaluation: get_usa_in_evaluation,
            EntryType.Certified: get_usa_certified,
            EntryType.Archived: get_usa_archived,
        },
    }

    @classmethod
    def from_dict(cls, dct):
        return cls(
            dct["country"],
            datetime.fromisoformat(dct["timestamp"]),
            {EntryType(entry_type): entries for entry_type, entries in dct["lists"].items()},
        )

    def to_dict(self):
        return {
            "country": self.country,
            "timestamp": self.timestamp.isoformat(),
            "lists": {entry_type.value: entries for entry_type, entries in self.lists.items()},
        }

    @classmethod
    def from_web(cls, scheme: str, entry_types: Iterable[EntryType]) -> CCScheme:
        if not (scheme_lists := cls.methods.get(scheme)):
            raise ValueError("Unknown scheme.")
        entries = {}
        timestamp = datetime.now()
        for each_type in entry_types:
            if not (method := scheme_lists.get(each_type)):
                raise ValueError("Wrong entry_type for scheme.")
            entries[each_type] = method()
        return cls(scheme, timestamp, entries)
