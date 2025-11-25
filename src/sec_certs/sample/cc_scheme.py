# This code is not a place of honor... no highly esteemed deed is commemorated here... nothing valued is here.
# What follows is a repulsive wall of BeautifulSoup garbage parsing code.
from __future__ import annotations

import hashlib
import math
import re
import tempfile
import warnings
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum
from inspect import signature
from pathlib import Path
from time import sleep
from typing import Any, ClassVar
from urllib.parse import urljoin

import requests
import tabula
from bs4 import BeautifulSoup, NavigableString, Tag
from dateutil.parser import isoparse
from requests import ConnectionError, HTTPError, Response
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from urllib3.connectionpool import InsecureRequestWarning

from sec_certs import constants
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils.helpers import parse_date
from sec_certs.utils.sanitization import sanitize_navigable_string as sns
from sec_certs.utils.tqdm import tqdm

__all__ = [
    "get_australia_in_evaluation",
    "get_canada_certified",
    "get_canada_in_evaluation",
    "get_france_certified",
    "get_france_archived",
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
    "get_poland_certified",
    "get_poland_ineval",
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

BASE_HEADERS = {"User-Agent": "sec-certs.org"}

SPOOF_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Dnt": "1",
    "Pragma": "no-cache",
    "Priority": "u=0, i",
    "Sec-Ch-Ua": 'Not?A_Brand";v="99", "Chromium";v="142',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Linux"',
}


def _getq(url: str, params, session=None, spoof=False, retries=0, **kwargs) -> Response:
    headers = {**BASE_HEADERS}
    if spoof:
        headers.update(SPOOF_HEADERS)
    with warnings.catch_warnings():
        while True:
            try:
                warnings.simplefilter("ignore", category=InsecureRequestWarning)
                conn = session if session else requests
                resp = conn.get(
                    url,
                    params=params,
                    headers=headers,
                    verify=False,
                    **kwargs,
                    timeout=10,
                )
                resp.raise_for_status()
            except (HTTPError, ConnectionError) as ex:
                if retries > 0:
                    retries -= 1
                    sleep(1)
                    continue
                raise ex
            return resp


def _get(url: str, session=None, **kwargs) -> Response:
    return _getq(url, None, session, **kwargs)


def _get_page(url: str, session=None, **kwargs) -> BeautifulSoup:
    return BeautifulSoup(_get(url, session, **kwargs).content, "html5lib")


def _get_hash(url: str, session=None, **kwargs) -> str | None:
    try:
        resp = _get(url, session, **kwargs)
    except (HTTPError, ConnectionError):
        return None
    h = hashlib.sha256()
    for chunk in resp.iter_content():
        h.update(chunk)
    return h.digest().hex()


def _setup_driver():
    # Use Selenium + Chrome to navigate ANSSI pages.
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    if "User-Agent" in SPOOF_HEADERS:
        options.add_argument(f"user-agent={SPOOF_HEADERS['User-Agent']}")

    # Try to create a Chrome webdriver and fail fast if unavailable.
    try:
        driver = webdriver.Chrome(options=options)
    except Exception as ex:
        raise RuntimeError("Selenium Chrome webdriver not available.") from ex

    return driver


def get_australia_in_evaluation(  # noqa: C901
    enhanced: bool = True,
) -> list[dict[str, Any]]:
    """
    Get Australia "products in evaluation" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :return: The entries.
    """
    session = requests.Session()
    soup = _get_page(constants.CC_AUSTRALIA_INEVAL_URL, session=session, spoof=True)
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
            "acceptance_date": parse_date(sns(tds[3].text), languages=["en"]),
            "evaluation_facility": sns(tds[4].text),
            "task_id": sns(tds[5].text),
        }
        if enhanced:
            e: dict[str, Any] = {}
            cert_page = _get_page(cert["url"], session=session, spoof=True)
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
                    e["category"] = val
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
    resp = _get(
        constants.CC_CANADA_API_URL + f"?lang=en&url={constants.CC_CANADA_CERTIFIED_URL}",
        None,
    )
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
            "certification_date": parse_date(sns(tds[3].text), "%Y-%m-%d"),
        }
        results.append(cert)
    return results


def get_canada_in_evaluation() -> list[dict[str, Any]]:
    """
    Get Canada "products in evaluation" entries.

    :return: The entries.
    """
    resp = _get(
        constants.CC_CANADA_API_URL + f"?lang=en&url={constants.CC_CANADA_INEVAL_URL}",
        None,
    )
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
            "evaluation_facility": sns(tds[3].text),
        }
        results.append(cert)
    return results


def _get_france(url, enhanced, artifacts, name) -> list[dict[str, Any]]:  # noqa: C901
    driver = _setup_driver()

    # Bypass Incapsula protection.
    driver.get(url)
    base_soup = BeautifulSoup(driver.page_source, "html5lib")

    # Continue with requests + BeautifulSoup.
    results: list[dict[str, Any]] = []
    pbar = tqdm(desc=f"Get FR scheme {name}.")

    pager = base_soup.find("nav", class_="pager")
    last_page_a = re.search("[0-9]+", pager.find("a", title="Aller à la dernière page").text)
    if not last_page_a:
        raise ValueError
    pages = int(last_page_a.group())
    session = requests.session()
    for page in range(pages + 1):
        page_url = url + f"?page={page}"
        driver.get(page_url)
        soup = BeautifulSoup(driver.page_source, "html5lib")
        session.cookies.clear()
        session.cookies.update({c["name"]: c["value"] for c in driver.get_cookies()})
        for row in soup.find_all("article", class_="node--type-produit-certifie-cc"):
            cert: dict[str, Any] = {
                "product": sns(row.find("h3").text),
                "url": urljoin(constants.CC_ANSSI_BASE_URL, row.find("a")["href"]),
            }
            description_para = row.find("p", class_="field-body")
            if description_para:
                cert["description"] = sns(description_para.text)
            complement_info = row.find("div", class_="info-complement")
            if complement_info:
                for li in complement_info.find_all("li"):
                    span = li.find("span")
                    if not span:
                        continue
                    label = span.text
                    value = sns(li.find(string=True, recursive=False))
                    if "Commanditaire" in label:
                        cert["sponsor"] = value
                    elif "Développeur" in label:
                        cert["developer"] = value
                    elif "Référence du certificat" in label:
                        cert["cert_id"] = value if not value or value.startswith("ANSSI") else "ANSSI-CC-" + value
                    elif "Niveau" in label:
                        cert["level"] = value
                    elif "Date de fin de validité" in label:
                        cert["expiration_date"] = parse_date(value, languages=["fr"])
            if enhanced:
                e: dict[str, Any] = {}
                driver.get(cert["url"])
                session.cookies.clear()
                session.cookies.update({c["name"]: c["value"] for c in driver.get_cookies()})
                cert_page = BeautifulSoup(driver.page_source, "html5lib")
                infos = cert_page.find("div", class_="product-infos-wrapper")
                if infos is None:
                    # Missing info block; skip enhanced parsing for this cert
                    cert["enhanced"] = e
                    pbar.update()
                    results.append(cert)
                    continue
                for tr in infos.find_all("tr"):
                    th = tr.find("th")
                    td = tr.find("td")
                    if not th or not td:
                        continue
                    label = th.text
                    value = sns(td.text)
                    if "Référence du certificat" in label:
                        e["cert_id"] = value if not value or value.startswith("ANSSI") else "ANSSI-CC-" + value
                    elif "Date de certification" in label:
                        e["certification_date"] = parse_date(value, languages=["fr"])
                    elif "Date de fin de validité" in label:
                        e["expiration_date"] = parse_date(value, languages=["fr"])
                    elif "Catégorie" in label:
                        e["category"] = value
                    elif "Référentiel" in label:
                        e["cc_version"] = value
                    elif "Développeur(s)" in label:
                        e["developer"] = value
                    elif "Commanditaire(s)" in label:
                        e["sponsor"] = value
                    elif "Centre d'évaluation" in label:
                        e["evaluation_facility"] = value
                    elif "Niveau" in label:
                        e["level"] = value
                    elif "Profil de protection" in label:
                        e["protection_profile"] = value
                    elif "Accords de reconnaissance" in label:
                        e["mutual_recognition"] = value
                    elif "Augmentations" in label:
                        e["augmented"] = value
                documents = cert_page.find("div", class_="documents")
                if documents:
                    for a in documents.find_all("a"):
                        if "Rapport de certification" in a.text:
                            e["report_link"] = urljoin(constants.CC_ANSSI_BASE_URL, a["href"])
                            if artifacts:
                                e["report_hash"] = _get_hash(e["report_link"], session=session, spoof=True)
                        elif "Cible de sécurité" in a.text:
                            e["target_link"] = urljoin(constants.CC_ANSSI_BASE_URL, a["href"])
                            if artifacts:
                                e["target_hash"] = _get_hash(e["target_link"], session=session, spoof=True)
                        elif "Certificat" in a.text:
                            e["cert_link"] = urljoin(constants.CC_ANSSI_BASE_URL, a["href"])
                            if artifacts:
                                e["cert_hash"] = _get_hash(e["cert_link"], session=session, spoof=True)
                cert["enhanced"] = e
            pbar.update()
            results.append(cert)
    driver.quit()
    return results


def get_france_certified(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:  # noqa: C901
    """
    Get French "certified product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_france(constants.CC_ANSSI_CERTIFIED_URL, enhanced, artifacts, "certified")


def get_france_archived(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:  # noqa: C901
    """
    Get French "archived product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_france(constants.CC_ANSSI_ARCHIVED_URL, enhanced, artifacts, "archived")


def get_germany_certified(  # noqa: C901
    enhanced: bool = True, artifacts: bool = False
) -> list[dict[str, Any]]:
    """
    Get German "certified product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    session = requests.Session()
    base_soup = _get_page(constants.CC_BSI_CERTIFIED_URL, session=session, spoof=True, retries=3)
    category_nav = base_soup.find("ul", class_="no-bullet row")
    results = []
    for li in tqdm(category_nav.find_all("li"), desc="Get DE scheme certified."):
        a = li.find("a")
        url = a["href"]
        category_name = sns(a.text)
        soup = _get_page(urljoin(constants.CC_BSI_BASE_URL, url), session=session, spoof=True, retries=3)
        content = soup.find("div", class_="content").find("div", class_="column")
        for table in tqdm(content.find_all("table"), leave=False):
            tbody = table.find("tbody")
            header = table.find_parent("div", class_="wrapperTable").find_previous_sibling("h2")
            for tr in tqdm(tbody.find_all("tr"), leave=False):
                tds = tr.find_all("td")
                if len(tds) != 4:
                    continue
                cert: dict[str, Any] = {
                    "cert_id": sns(tds[0].text),
                    "product": sns(tds[1].text),
                    "vendor": sns(tds[2].text),
                    "certification_date": parse_date(sns(tds[3].text), "%d.%m.%Y"),
                    "category": category_name,
                    "url": urljoin(constants.CC_BSI_BASE_URL, tds[0].find("a")["href"]),
                }
                if enhanced:
                    e: dict[str, Any] = {}
                    cert_page = _get_page(cert["url"], session=session, spoof=True, retries=3)
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
                            e["certification_date"] = parse_date(value, "%d.%m.%Y")
                        elif "valid until" in title:
                            e["expiration_date"] = parse_date(value, "%d.%m.%Y")
                    links = content.find("ul")
                    if links:
                        # has multiple entries/recertifications
                        e["entries"] = []
                        for link_li in links.find_all("li"):
                            children = list(link_li.children)
                            if not children:
                                continue
                            first_child = children[0]
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
                                e["report_hash"] = _get_hash(href, session=session, spoof=True, retries=3)
                        elif "Security Target" in title:
                            e["target_link"] = href
                            if artifacts:
                                e["target_hash"] = _get_hash(href, session=session, spoof=True, retries=3)
                        elif "Certificate" in title:
                            e["cert_link"] = href
                            if artifacts:
                                e["cert_hash"] = _get_hash(href, session=session, spoof=True, retries=3)
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
    pbar = tqdm(desc="Get IN scheme certified.")
    while pages:
        page = pages.pop()
        seen_pages.add(page)
        url = constants.CC_INDIA_CERTIFIED_URL + f"?page={page}"
        soup = _get_page(url)

        # Update pages
        pager = soup.find("ul", class_="pager__items")
        if pager:
            for li in pager.find_all("li"):
                try:
                    new_page = int(li.find("a")["href"].split("=")[1])
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
                "certification_date": parse_date(sns(tds[5].text), "%d-%b-%Y"),
                "report_link": urljoin(constants.CC_INDIA_BASE_URL, _fix_india_link(report_a["href"])),
                "report_name": sns(report_a.text),
                "target_link": urljoin(constants.CC_INDIA_BASE_URL, _fix_india_link(target_a["href"])),
                "target_name": sns(target_a.text),
                "cert_link": urljoin(constants.CC_INDIA_BASE_URL, _fix_india_link(cert_a["href"])),
                "cert_name": sns(cert_a.text),
            }
            pbar.update()
            results.append(cert)
    pbar.close()
    return results


def get_india_archived() -> list[dict[str, Any]]:
    """
    Get Indian "archived product" entries.

    :return: The entries.
    """
    pages = {0}
    seen_pages = set()
    results = []
    pbar = tqdm(desc="Get IN scheme archived.")
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
                    new_page = int(li.find("a")["href"].split("=")[1])
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
                "certification_date": parse_date(sns(tds[8].text), "%d/%b/%Y"),
            }
            if report_a:
                cert["report_link"] = urljoin(constants.CC_INDIA_BASE_URL, _fix_india_link(report_a["href"]))
                cert["report_name"] = sns(report_a.text)
            pbar.update()
            results.append(cert)
    pbar.close()
    return results


def get_italy_certified() -> list[dict[str, Any]]:  # noqa: C901
    """
    Get Italian "certified product" entries.

    :return: The entries.
    """
    soup = _get_page(constants.CC_ITALY_CERTIFIED_URL)
    div = soup.find("div", class_="certificati")
    results = []
    for cert_div in tqdm(div.find_all("div", recursive=False), desc="Get IT scheme certified."):
        title = cert_div.find("h3").text
        data_div = cert_div.find("div", class_="collapse")
        cert = {"title": title}
        for data_p in data_div.find_all("p"):
            p_text = sns(data_p.text)
            if not p_text or ":" not in p_text:
                continue
            p_name, p_data = p_text.split(":")
            p_data = p_data.strip()
            p_link = data_p.find("a")
            if "Fornitore" in p_name:
                cert["supplier"] = p_data
            elif "Livello di garanzia" in p_name:
                cert["level"] = p_data
            elif "Data emissione certificato" in p_name:
                cert["certification_date"] = parse_date(p_data, languages=["it"])
            elif "Data revisione" in p_name:
                cert["revision_date"] = parse_date(p_data, languages=["it"])
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
    for cert_div in tqdm(div.find_all("div", recursive=False), desc="Get IT scheme in evaluation."):
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


def _get_japan(url, enhanced, artifacts, name) -> list[dict[str, Any]]:  # noqa: C901
    session = requests.Session()
    soup = _get_page(url, session=session)
    table = soup.find("table", class_="cert-table")
    results = []
    trs = list(table.find_all("tr"))
    for tr in tqdm(trs, desc=f"Get JP scheme {name}."):
        tds = tr.find_all("td")
        if not tds:
            continue
        if len(tds) in (6, 7):
            cert_id = sns(tds[0].text)
            if cert_id:
                cert_id = "JISEC-CC-CRP-" + cert_id
            cert: dict[str, Any] = {
                "cert_id": cert_id,
                "supplier": sns(tds[1].text),
                "toe_overseas_name": sns(tds[2].text),
            }
            if len(tds) == 6:
                cert["expiration_date"] = parse_date(sns(tds[5].text), "%Y-%m")
                cert["claim"] = sns(tds[4].text)
            else:
                cert["expiration_date"] = parse_date(sns(tds[4].text), "%Y-%m")
                cert["claim"] = sns(tds[5].text)
            cert_date = sns(tds[3].text)
            toe_a = tds[2].find("a")
            if toe_a and "href" in toe_a.attrs:
                toe_link = urljoin(constants.CC_JAPAN_CERT_BASE_URL, toe_a["href"])
            else:
                toe_link = None
            if cert_date and "Assurance Continuity" in cert_date:
                cert["revalidations"] = [{"date": cert_date.split("(")[0], "link": toe_link}]
            else:
                cert["certification_date"] = parse_date(cert_date, "%Y-%m")
                cert["toe_overseas_link"] = toe_link
            results.append(cert)
        if len(tds) == 1:
            cert = results[-1]
            cert["toe_japan_name"] = sns(tds[0].text)
            toe_a = tds[0].find("a")
            if toe_a and "href" in toe_a.attrs:
                cert["toe_japan_link"] = urljoin(constants.CC_JAPAN_BASE_URL, toe_a["href"])
        if len(tds) == 2:
            cert = results[-1]
            cert["certification_date"] = parse_date(sns(tds[1].text), "%Y-%m")
            toe_a = tds[0].find("a")
            if toe_a and "href" in toe_a.attrs:
                toe_link = urljoin(constants.CC_JAPAN_BASE_URL, toe_a["href"])
            else:
                toe_link = None
            cert["toe_overseas_link"] = toe_link
    if enhanced:
        for cert in tqdm(results, desc=f"Get JP scheme {name} (enhanced)."):
            e: dict[str, Any] = {}
            cert_link = cert.get("toe_overseas_link") or cert.get("toe_japan_link")
            if not cert_link:
                continue
            cert_page = _get_page(cert_link, session=session)
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
                    if not value or value.startswith("JISEC-CC-CRP-"):
                        e["cert_id"] = value
                    elif value.startswith("JISEC-"):
                        e["cert_id"] = value.replace("JISEC-", "JISEC-CC-CRP-")
                    else:
                        e["cert_id"] = value
                elif "Version of Common Criteria" in title:
                    e["cc_version"] = value
                elif "Date of Certification Expiry" in title:
                    e["expiration_date"] = parse_date(value, "%Y-%m-%d")
                elif "Date of Certification" in title:
                    e["certification_date"] = parse_date(value, "%Y-%m-%d")
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
                            e["report_hash"] = _get_hash(e["report_link"], session=session)
                    elif "Certificate" in name:
                        e["cert_link"] = urljoin(constants.CC_JAPAN_BASE_URL, li_a["href"])
                        if artifacts:
                            e["cert_hash"] = _get_hash(e["cert_link"], session=session)
                    elif "Target" in name:
                        e["target_link"] = urljoin(constants.CC_JAPAN_BASE_URL, li_a["href"])
                        if artifacts:
                            e["target_hash"] = _get_hash(e["target_link"], session=session)
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
    japan_hw = _get_japan(constants.CC_JAPAN_CERTIFIED_HW_URL, enhanced, artifacts, "certified HW")
    japan_sw = _get_japan(constants.CC_JAPAN_CERTIFIED_SW_URL, enhanced, artifacts, "certified SW")
    return japan_sw + japan_hw


def get_japan_archived(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Japanese "archived product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_japan(constants.CC_JAPAN_ARCHIVED_SW_URL, enhanced, artifacts, "archived SW")


def get_japan_in_evaluation() -> list[dict[str, Any]]:
    """
    Get Japanese "product in evaluation" entries.

    :return: The entries.
    """
    soup = _get_page(constants.CC_JAPAN_INEVAL_URL)
    table = soup.find("table")
    results = []
    for tr in tqdm(table.find_all("tr"), desc="Get JP scheme in evaluation."):
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


def _get_malaysia(url, enhanced, artifacts, name) -> list[dict[str, Any]]:  # noqa: C901
    session = requests.Session()
    soup = _get_page(url + "?limit=0&start=0", session=session)
    results = []
    pbar = tqdm(desc=f"Get MY scheme {name}.")
    table = soup.find("table", class_="directoryTable")
    for tr in table.find_all("tr", class_="directoryRow"):
        tds = tr.find_all("td")
        cert: dict[str, Any] = {
            "cert_no": sns(tds[0].text),
            "developer": sns(tds[1].text),
            "level": sns(tds[2].text),
            "product": sns(tds[3].text),
            "certification_date": parse_date(sns(tds[4].text), "%d-%m-%Y"),
            "expiration_date": parse_date(sns(tds[5].text), "%d-%m-%Y"),
            "recognition": sns(tds[6].text),
            "url": urljoin(constants.CC_MALAYSIA_BASE_URL, tds[7].find("a")["href"]),
        }
        if enhanced:
            e: dict[str, Any] = {}
            cert_page = _get_page(cert["url"], session=session)
            for row in cert_page.find_all("div", class_="rsform-table-row"):
                left = row.find("div", class_="rsform-left-col")
                right = row.find("div", class_="rsform-right-col")
                title = left.text
                value = sns(right.text)
                if "Project ID" in title:
                    e["cert_id"] = value
                elif "Product Name and Version" in title:
                    e["product"] = sns(right.text)
                elif "Product Sponsor / Developer" in title:
                    e["developer"] = value
                elif "Category" in title:
                    e["category"] = value
                elif "Product Type" in title:
                    e["type"] = value
                elif "Scope" in title:
                    e["scope"] = value
                elif "Product Sponsor / Developer Contact Details" in title:
                    e["developer_contact"] = value
                elif "Assurance Level" in title:
                    e["assurance_level"] = value
                elif "Certificate Date" in title:
                    e["certification_date"] = parse_date(value, "%d-%m-%Y")
                elif "Expiry Date" in title:
                    e["expiration_date"] = parse_date(value, "%d-%m-%Y")
                elif "Recognized By" in title:
                    e["mutual_recognition"] = value
                elif "Reports" in title:
                    for a in right.find_all("a"):
                        if "ST" in a.text:
                            e["target_link"] = urljoin(constants.CC_MALAYSIA_BASE_URL, a["href"])
                            if artifacts:
                                e["target_hash"] = _get_hash(e["target_link"], session=session)
                        elif "CR" in a.text:
                            e["report_link"] = urljoin(constants.CC_MALAYSIA_BASE_URL, a["href"])
                            if artifacts:
                                e["report_hash"] = _get_hash(e["report_link"], session=session)
                elif "Maintenance" in title:
                    pass
                elif "Status" in title:
                    e["status"] = value
            cert["enhanced"] = e
        pbar.update()
        results.append(cert)
    pbar.close()
    return results


def get_malaysia_certified(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Malaysian "certified product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_malaysia(constants.CC_MALAYSIA_CERTIFIED_URL, enhanced, artifacts, "certified")


def get_malaysia_archived(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Malaysian "archived product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_malaysia(constants.CC_MALAYSIA_ARCHIVED_URL, enhanced, artifacts, "archived")


def get_malaysia_in_evaluation() -> list[dict[str, Any]]:
    """
    Get Malaysian "product in evaluation" entries.

    :return: The entries.
    """
    soup = _get_page(constants.CC_MALAYSIA_INEVAL_URL)
    main_div = soup.find("div", attrs={"itemprop": "articleBody"})
    table = main_div.find("table")
    results = []
    for tr in tqdm(table.find_all("tr")[1:], desc="Get MY scheme in evaluation."):
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


def _get_netherlands_certified_old(  # noqa: C901
    artifacts: bool = False,
) -> list[dict[str, Any]]:
    soup = _get_page(constants.CC_NETHERLANDS_OLD_CERTIFIED_URL)
    main_div = soup.select("body > main > div > div > div > div:nth-child(2) > div.col-lg-9 > div:nth-child(3)")[0]
    rows = main_div.find_all("div", class_="row", recursive=False)
    modals = main_div.find_all("div", class_="modal", recursive=False)
    results = []
    for row, modal in tqdm(zip(rows, modals), desc="Get NL scheme certified (old)."):
        row_entries = row.find_all("a")
        modal_trs = modal.find_all("tr")
        cert_id = sns(row_entries[3].text)
        if cert_id:
            cert_id = cert_id if cert_id.startswith("NSCIB-") else "NSCIB-" + cert_id
            cert_id = cert_id if cert_id.endswith("-CR") else cert_id + "-CR"
        cert: dict[str, Any] = {
            "manufacturer": sns(row_entries[0].text),
            "product": sns(row_entries[1].text),
            "scheme": sns(row_entries[2].text),
            "cert_id": cert_id,
        }
        for tr in modal_trs:
            th_text = tr.find("th").text
            td = tr.find("td")
            if "Manufacturer website" in th_text:
                cert["manufacturer_link"] = td.find("a")["href"]
            elif "Assurancelevel" in th_text:
                cert["level"] = sns(td.text)
            elif "Certificate" in th_text:
                cert["cert_link"] = urljoin(constants.CC_NETHERLANDS_OLD_BASE_URL, td.find("a")["href"])
                if artifacts:
                    cert["cert_hash"] = _get_hash(cert["cert_link"])
            elif "Certificationreport" in th_text:
                cert["report_link"] = urljoin(constants.CC_NETHERLANDS_OLD_BASE_URL, td.find("a")["href"])
                if artifacts:
                    cert["report_hash"] = _get_hash(cert["report_link"])
            elif "Securitytarget" in th_text:
                cert["target_link"] = urljoin(constants.CC_NETHERLANDS_OLD_BASE_URL, td.find("a")["href"])
                if artifacts:
                    cert["target_hash"] = _get_hash(cert["target_link"])
            elif "Maintenance report" in th_text:
                cert["maintenance_link"] = urljoin(constants.CC_NETHERLANDS_OLD_BASE_URL, td.find("a")["href"])
                if artifacts:
                    cert["maintenance_hash"] = _get_hash(cert["maintenance_link"])
        results.append(cert)
    return results


def _get_netherlands_certified_new(  # noqa: C901
    artifacts: bool = False,
) -> list[dict[str, Any]]:
    soup = _get_page(constants.CC_NETHERLANDS_NEW_CERTIFIED_URL)
    table = soup.find("table", class_="wpDataTable")
    results = []
    for tr in tqdm(table.find_all("tr")[1:], desc="Get NL scheme certified (new)."):
        tds = tr.find_all("td")
        cert_id = sns(tds[0].text).replace("\n", "")  # type: ignore
        cert_id = cert_id if cert_id.startswith("NSCIB-") else "NSCIB-" + cert_id
        cert_id = cert_id if cert_id.endswith("-CR") else cert_id + "-CR"
        cert = {
            "cert_id": cert_id,
            "certification_date": parse_date(sns(tds[1].text), "%Y-%m-%d"),
            "status": sns(tds[2].text),
            "product": sns(tds[3].text),
            "developer": sns(tds[4].text),
            "evaluation_facility": sns(tds[5].text),
            "level": sns(tds[6].text),
        }
        for name, i in (("cert", 7), ("report", 8), ("target", 9)):
            a = tds[i].find("a")
            if a:
                href = urljoin(constants.CC_NETHERLANDS_NEW_BASE_URL, a["href"])
                cert[f"{name}_link"] = href
                if artifacts:
                    cert[f"{name}_hash"] = _get_hash(href)
        results.append(cert)
    return results


def get_netherlands_certified(artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Dutch "certified product" entries.

    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    old = _get_netherlands_certified_old(artifacts=artifacts)
    new = _get_netherlands_certified_new(artifacts=artifacts)
    return old + new


def _get_netherlands_in_evaluation_old() -> list[dict[str, Any]]:
    soup = _get_page(constants.CC_NETHERLANDS_OLD_INEVAL_URL)
    table = soup.find("table")
    results = []
    for tr in tqdm(table.find_all("tr")[1:], desc="Get NL scheme in evaluation (old)."):
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


def _get_netherlands_in_evaluation_new() -> list[dict[str, Any]]:
    soup = _get_page(constants.CC_NETHERLANDS_NEW_INEVAL_URL)
    table = soup.find("table", class_="wpDataTable")
    results = []
    for tr in tqdm(table.find_all("tr")[1:], desc="Get NL scheme in evaluation (new)."):
        tds = tr.find_all("td")
        cert = {
            "cert_id": sns(tds[0].text),
            "developer": sns(tds[1].text),
            "product": sns(tds[2].text),
            "category": sns(tds[3].text),
            "level": sns(tds[4].text),
        }
        results.append(cert)
    return results


def get_netherlands_in_evaluation() -> list[dict[str, Any]]:
    """
    Get Dutch "product in evaluation" entries.

    :return: The entries.
    """
    old = _get_netherlands_in_evaluation_old()
    new = _get_netherlands_in_evaluation_new()
    return old + new


def _get_norway(  # noqa: C901
    url: str, enhanced: bool, artifacts: bool, name
) -> list[dict[str, Any]]:
    session = requests.Session()
    soup = _get_page(url, session=session)
    results = []
    for tr in tqdm(soup.find_all("tr", class_="certified-product"), desc=f"Get NO scheme {name}."):
        tds = tr.find_all("td")
        cert: dict[str, Any] = {
            "product": sns(tds[0].text),
            "url": tds[0].find("a")["href"],
            "category": sns(tds[1].find("p", class_="value").text),
            "developer": sns(tds[2].find("p", class_="value").text),
            "certification_date": parse_date(sns(tds[3].find("time").text), "%d.%m.%Y"),
        }
        if enhanced:
            e: dict[str, Any] = {}
            cert_page = _get_page(cert["url"], session=session)
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
                    value = value.split(" ")[0]
                    e["cert_id"] = value if value.startswith("SERTIT-") else "SERTIT-" + value
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
                    e["certification_date"] = parse_date(value, "%d.%m.%Y")
                elif "Certificate Expiration Date" in title:
                    e["expiration_date"] = parse_date(value, "%d.%m.%Y")
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
                        entry["hash"] = _get_hash(entry["href"], session=session)  # type: ignore
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
    return _get_norway(constants.CC_NORWAY_CERTIFIED_URL, enhanced, artifacts, "certified")


def get_norway_archived(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Norwegian "archived product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_norway(constants.CC_NORWAY_ARCHIVED_URL, enhanced, artifacts, "archived")


def _get_korea(  # noqa: C901
    url: str, product_class: int, enhanced: bool, artifacts: bool, name
) -> list[dict[str, Any]]:
    session = requests.Session()
    _get_page(constants.CC_KOREA_EN_URL, session=session)
    # Get base page
    url = url + f"?product_class={product_class}"
    soup = _get_page(url, session=session)
    seen_pages = set()
    pages = {1}
    results = []
    pbar = tqdm(desc=f"Get KR scheme {name}.")
    while pages:
        page = pages.pop()
        csrf = soup.find("form", id="fm").find("input", attrs={"name": "csrf"})["value"]
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=InsecureRequestWarning)
            resp = session.post(
                url, data={"csrf": csrf, "selectPage": page, "product_class": product_class}, verify=False
            )
        soup = BeautifulSoup(resp.content, "html5lib")
        tbody = soup.find("table", class_="cpl").find("tbody")
        for tr in tbody.find_all("tr"):
            tds = tr.find_all("td")
            if len(tds) != 6:
                continue
            link = tds[0].find("a")
            id = link["id"].split("-")[1]
            cert_id = sns(tds[1].text)
            if cert_id:
                cert_id = cert_id.replace(" ", "-")
            cert: dict[str, Any] = {
                "product": sns(tds[0].text),
                "cert_id": cert_id,
                "product_link": constants.CC_KOREA_PRODUCT_URL.format(id, product_class),
                "vendor": sns(tds[2].text),
                "level": sns(tds[3].text),
                "category": sns(tds[4].text),
                "certification_date": parse_date(sns(tds[5].text), "%Y-%m-%d"),
            }
            if enhanced:
                e: dict[str, Any] = {}
                if not cert["product_link"]:
                    continue
                cert_page = _get_page(cert["product_link"], session=session)
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
                        v["certification_date"] = parse_date(value, "%Y-%m-%d")
                    elif "EvaluationAssurance Level" in title:
                        v["assurance_level"] = value
                    elif "Expiry Date" in title:
                        v["expiration_date"] = parse_date(value, "%Y-%m-%d")
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
                            v["cert_hash"] = _get_hash(v["cert_link"], session)
                    elif "Security Target" in title and a:
                        v["target_link"] = urljoin(constants.CC_KOREA_BASE_URL, a["href"])
                        if artifacts:
                            v["target_hash"] = _get_hash(v["target_link"], session)
                    elif "Certification Report" in title and a:
                        v["report_link"] = urljoin(constants.CC_KOREA_BASE_URL, a["href"])
                        if artifacts:
                            v["report_hash"] = _get_hash(v["report_link"], session)
                    elif "Maintenance Report" in title and a:
                        v["maintenance_link"] = urljoin(constants.CC_KOREA_BASE_URL, a["href"])
                        if artifacts:
                            v["maintenance_hash"] = _get_hash(v["maintenance_link"], session)
                cert["enhanced"] = e
            pbar.update()
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
    pbar.close()
    return results


def get_korea_certified(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Korean "certified product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_korea(
        constants.CC_KOREA_CERTIFIED_URL, product_class=1, enhanced=enhanced, artifacts=artifacts, name="certified"
    )


def get_korea_suspended(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Korean "suspended product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_korea(
        constants.CC_KOREA_SUSPENDED_URL, product_class=2, enhanced=enhanced, artifacts=artifacts, name="suspended"
    )


def get_korea_archived(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Korean "product in evaluation" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_korea(
        constants.CC_KOREA_ARCHIVED_URL, product_class=4, enhanced=enhanced, artifacts=artifacts, name="archived"
    )


def get_poland_certified(artifacts: bool = False) -> list[dict[str, Any]]:  # noqa: C901
    """
    Get Polish "certified product" entries.

    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    soup = _get_page(constants.CC_POLAND_CERTIFIED_URL)
    accordion = soup.find("div", class_="gs-accordion")
    results = []
    for div in tqdm(accordion.find_all("div", class_="gs-accordion-item"), desc="Get PL scheme certified."):
        head = sns(div.find("div", class_="gs-accordion-item__heading").text)
        cert = {"product": head}
        for row in div.find_all("div", class_="gspb_row"):
            ps = list(row.find_all("p"))
            label = sns(ps[0].text)
            val = sns(ps[1].text)
            a = ps[1].find("a")
            href = urljoin(constants.CC_POLAND_BASE_URL, a["href"]) if a else None
            if label == "Client’s name and address":
                cert["client"] = val
            elif label == "Certification scope":
                cc_entry = val
                cc_split = None
                if cc_entry and "\n" in cc_entry:
                    cc_split = cc_entry.split("\n")
                elif cc_entry and "," in cc_entry:
                    cc_split = cc_entry.split(",")
                if cc_split:
                    cert["cc_version"] = cc_split[0].strip()
                    cert["assurance_level"] = ", ".join(cc_split[1:]).strip()
            elif label == "Certificate decision date":
                cert["decision_date"] = parse_date(val, "%d.%m.%Y")
            elif label == "Certificate issue date":
                cert["certification_date"] = parse_date(val, "%d.%m.%Y")
            elif label == "End of validity":
                cert["expiration_date"] = parse_date(val, "%d.%m.%Y")
            elif label == "Certification Report" and href:
                cert["report_link"] = href
                if artifacts:
                    cert["report_hash"] = _get_hash(href)
            elif label == "Security Target" and href:
                cert["target_link"] = href
                if artifacts:
                    cert["target_hash"] = _get_hash(href)
            elif label == "Certificate" and href:
                cert["cert_link"] = href
                if artifacts:
                    cert["cert_hash"] = _get_hash(href)
        results.append(cert)
    return results


def get_poland_ineval() -> list[dict[str, Any]]:
    """
    Get Polish "product in evaluation" entries.

    :return: The entries.
    """
    soup = _get_page(constants.CC_POLAND_INEVAL_URL)
    accordion = soup.find("div", class_="gs-accordion")
    results = []
    for div in tqdm(accordion.find_all("div", class_="gs-accordion-item"), desc="Get PL scheme in evaluation."):
        head = sns(div.find("div", class_="gs-accordion-item__heading").text)
        cert = {"client": head}
        for row in div.find_all("div", class_="gspb_row"):
            one = row.find("div", class_="gspb_row__content")
            ps = list(one.find_all("div", recursive=False))
            label = sns(ps[0].text)
            val = sns(ps[1].text)
            if label == "Product, version":
                cert["product"] = val
            elif label == "Certification scope":
                cc_entry = val
                cc_split = None
                if cc_entry and "\n" in cc_entry:
                    cc_split = cc_entry.split("\n")
                elif cc_entry and "," in cc_entry:
                    cc_split = cc_entry.split(",")
                if cc_split:
                    cert["cc_version"] = cc_split[0].strip()
                    cert["assurance_level"] = ", ".join(cc_split[1:]).strip()
        results.append(cert)
    return results


def _get_singapore(url: str, enhanced: bool, artifacts: bool, name) -> list[dict[str, Any]]:  # noqa: C901
    driver = _setup_driver()

    driver.get(url)
    current = 1
    results: list[dict[str, Any]] = []
    pbar = tqdm(desc=f"Get SG scheme {name}.")
    while True:
        driver.get(f"{url}?page={current}")
        sleep(2)
        soup = BeautifulSoup(driver.page_source, "html5lib")
        if "We couldn’t find any articles" in soup.text:
            break
        main = soup.find("main", id="main-content")
        links = main.find_all("a", class_="outline", href=True)
        for link in links:
            if not link["href"].startswith(
                "/our-programmes/certification-and-labelling-schemes/singapore-common-criteria-scheme/product"
            ):
                continue
            cert: dict[str, Any] = {
                "url": urljoin(constants.CC_SINGAPORE_BASE_URL, link["href"]),
                "product": sns(link.find("h3").text),
            }
            ps = link.find_all("p")
            ps.pop(0)
            while ps:
                p = ps.pop(0)
                text: str = sns(p.text)  # type: ignore
                if "Assurance Level" in text:
                    val = ps.pop(0)
                    cert["level"] = sns(val)
                elif "Product Developer" in text:
                    val = ps.pop(0)
                    cert["vendor"] = sns(val)
                elif "Date of" in text:
                    match = re.match(
                        "Date of Certificate Issuance: (?P<issue_date>.+) Date of Certificate Expiry: (?P<expiry_date>.+)",
                        text,
                    )
                    if not match:
                        continue
                    cert["certification_date"] = parse_date(match.group("issue_date"), "%d %B %Y")
                    cert["expiration_date"] = parse_date(match.group("expiry_date"), "%d %B %Y")
            if enhanced:
                e: dict[str, Any] = {}
                driver.get(cert["url"])
                sleep(2)
                cert_soup = BeautifulSoup(driver.page_source, "html5lib")
                for li in cert_soup.find("main", id="main-content").find("ul", class_="list-disc"):
                    if "Security Target" in li.text:
                        a = li.find("a")
                        e["target_title"] = sns(a.text)
                        e["target_link"] = urljoin(constants.CC_SINGAPORE_BASE_URL, a["href"])
                        if artifacts:
                            e["target_hash"] = _get_hash(e["target_link"])
                    elif "Certification Report" in li.text:
                        a = li.find("a")
                        e["report_title"] = sns(a.text)
                        e["report_link"] = urljoin(constants.CC_SINGAPORE_BASE_URL, a["href"])
                        if artifacts:
                            e["report_hash"] = _get_hash(e["report_link"])
                    elif "Certificate" in li.text:
                        a = li.find("a")
                        e["cert_title"] = sns(a.text)
                        e["cert_link"] = urljoin(constants.CC_SINGAPORE_BASE_URL, a["href"])
                        if artifacts:
                            e["cert_hash"] = _get_hash(e["cert_link"])
                cert["enhanced"] = e
            results.append(cert)
            pbar.update()
        current += 1
    pbar.close()
    driver.quit()
    return results


def get_singapore_certified(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Singaporean "certified product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_singapore(constants.CC_SINGAPORE_CERTIFIED_URL, enhanced, artifacts, "certified")


def get_singapore_in_evaluation() -> list[dict[str, Any]]:
    """
    Get Singaporean "product in evaluation" entries.

    :return: The entries.
    """
    soup = _get_page(constants.CC_SINGAPORE_INEVAL_URL)
    table = soup.find("table")
    results = []
    for tr in tqdm(table.find_all("tr")[1:], desc="Get SG scheme in evaluation."):
        tds = tr.find_all("td")
        cert = {
            "name": sns(tds[0].text),
            "vendor": sns(tds[1].text),
            "level": sns(tds[2].text),
        }
        results.append(cert)
    return results


def get_singapore_archived(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Singaporean "archived product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_singapore(constants.CC_SINGAPORE_ARCHIVED_URL, enhanced, artifacts, "archived")


def get_spain_certified(enhanced: bool = True) -> list[dict[str, Any]]:  # noqa: C901
    """
    Get Spanish "certified product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :return: The entries.
    """
    session = requests.Session()
    soup = _get_page(constants.CC_SPAIN_CERTIFIED_URL, session=session)
    tbody = soup.find("table", class_="djc_items_table").find("tbody")
    results = []
    for tr in tqdm(tbody.find_all("tr", recursive=False), desc="Get ES scheme certified."):
        tds = tr.find_all("td")
        cert = {
            "product": sns(tds[0].text),
            "product_link": urljoin(constants.CC_SPAIN_BASE_URL, tds[0].find("a")["href"]),
            "category": sns(tds[1].text),
            "manufacturer": sns(tds[2].text),
            "certification_date": parse_date(sns(tds[3].text), "%d/%m/%Y"),
        }
        if enhanced:
            e: dict[str, Any] = {}
            if not cert["product_link"]:
                continue
            cert_page = _get_page(cert["product_link"], session=session)
            description_div = cert_page.find("div", class_="djc_description")
            e["description"] = sns(description_div.find("div", class_="djc_desc_wrap").text)
            category_a = description_div.find("div", class_="djc_category_info").find("a")
            if category_a:
                e["category"] = sns(category_a.text)
            e["manufacturer"] = sns(description_div.find("div", class_="djc_producer_info").find("span").text)
            for attr in description_div.find_all("p", class_="djc_attribute"):
                label_text = sns(attr.find("span", class_="djc_attribute-label").text)
                value = sns(attr.find("span", class_="djc_value").text)
                if not label_text:
                    continue
                if "Type" in label_text:
                    e["type"] = value
                elif "Testing laboratory" in label_text:
                    e["evaluation_facility"] = value
                elif "Certification Status" in label_text:
                    e["status"] = value
                elif "Certification Date" in label_text:
                    e["certification_date"] = parse_date(value, "%d-%m-%Y")
                elif "Standard Version" in label_text:
                    e["cc_version"] = value
                elif "Evaluation Level" in label_text:
                    e["level"] = value
            for file in description_div.find_all("p", class_="djc_file"):
                label_text = sns(file.find("span", class_="djc_att_group_label").text)
                if not label_text:
                    continue
                if "CCRA Certificate" in label_text:
                    file_type = "cert"
                elif "Security Target" in label_text:
                    file_type = "target"
                elif "Certification Report" in label_text:
                    file_type = "report"
                else:
                    continue
                e[f"{file_type}_link"] = urljoin(constants.CC_SPAIN_BASE_URL, file.find("a")["href"])
            cert["enhanced"] = e
        results.append(cert)
    return results


def _get_sweden(  # noqa: C901
    url: str, enhanced: bool, artifacts: bool, name
) -> list[dict[str, Any]]:
    session = requests.Session()
    soup = _get_page(url, session=session)
    nav = soup.find("main").find("nav", class_="component-nav-box__list")
    results = []
    for link in tqdm(nav.find_all("a"), desc=f"Get SE scheme {name}."):
        cert: dict[str, Any] = {
            "product": sns(link.text),
            "url": urljoin(constants.CC_SWEDEN_BASE_URL, link["href"]),
        }
        if enhanced:
            e: dict[str, Any] = {}
            if not cert["url"]:
                continue
            cert_page = _get_page(cert["url"], session=session)
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
                        e["certification_date"] = parse_date(value, "%Y-%m-%d")
                    elif "Sponsor" in title:
                        e["sponsor"] = value
                    elif "Utvecklare" in title:
                        e["developer"] = value
                    elif "Evalueringsföretag" in title:
                        e["evaluation_facility"] = value
                    elif "Security Target" in title and a:
                        e["target_link"] = urljoin(constants.CC_SWEDEN_BASE_URL, a["href"])
                        if artifacts:
                            e["target_hash"] = _get_hash(e["target_link"], session=session)
                    elif "Certifieringsrapport" in title and a:
                        e["report_link"] = urljoin(constants.CC_SWEDEN_BASE_URL, a["href"])
                        if artifacts:
                            e["report_hash"] = _get_hash(e["report_hash"], session=session)
                    elif "Certifikat" in title and a:
                        e["cert_link"] = urljoin(constants.CC_SWEDEN_BASE_URL, a["href"])
                        if artifacts:
                            e["cert_hash"] = _get_hash(e["cert_link"], session=session)
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
    return _get_sweden(constants.CC_SWEDEN_CERTIFIED_URL, enhanced, artifacts, "certified")


def get_sweden_in_evaluation(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Swedish "product in evaluation" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_sweden(constants.CC_SWEDEN_INEVAL_URL, enhanced, artifacts, "in evaluation")


def get_sweden_archived(enhanced: bool = True, artifacts: bool = False) -> list[dict[str, Any]]:
    """
    Get Swedish "archived product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_sweden(constants.CC_SWEDEN_ARCHIVED_URL, enhanced, artifacts, "archived")


def get_turkey_certified() -> list[dict[str, Any]]:
    """
    Get Turkish "certified product" entries.

    :return: The entries.
    """
    results = []
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "turkey.pdf"
        resp = requests.get(constants.CC_TURKEY_ARCHIVED_URL)
        resp.raise_for_status()
        with pdf_path.open("wb") as f:
            f.write(resp.content)
        dfs = tabula.read_pdf(str(pdf_path), pages="all")
        for df in tqdm(dfs, desc="Get TR scheme certified."):
            for line in df.values:  # type: ignore
                values = [value if not (isinstance(value, float) and math.isnan(value)) else None for value in line]
                cert = {
                    # TODO: Split item number and generate several dicts for a range they include.
                    "item_no": values[0],
                    "developer": values[1],
                    "product": values[2],
                    "cc_version": values[3],
                    "level": values[4],
                    "evaluation_facility": values[5],
                    "certification_date": values[6],
                    "expiration_date": values[7],
                    # TODO: Parse "Ongoing Evaluation" out of this field as well.
                    "archived": isinstance(values[9], str) and "Archived" in values[9],
                }
                results.append(cert)
    return results


def _get_usa(args, enhanced: bool, artifacts: bool, name):  # noqa: C901
    # TODO: There is more information in the API (like about PPs, etc.)
    def map_cert(cert, files=None):  # noqa: C901
        result = {
            "product": cert["product_name"],
            "id": f"CCEVS-VR-VID{cert['product_id']}",
            "url": urljoin(constants.CC_USA_BASE_URL, f"/product/{cert['product_id']}"),
            "certification_date": parse_date(cert["certification_date"], "%m/%d/%Y"),
            "expiration_date": parse_date(cert["sunset_date"], "%m/%d/%Y"),
            "category": cert["tech_type"],
            "vendor": cert["vendor_id_name"],
            "evaluation_facility": cert["assigned_lab_name"],
            "scheme": cert["submitting_country_id_code"],
        }
        if files:
            for file in files["eval_files"]:
                if file["file_label"] == "Validation Report":
                    dt = isoparse(file["uploaded_on"])
                    result["id"] += f"-{dt.year}"
                    result["report_link"] = constants.CC_USA_GETFILE_URL + f"?file_id={file['file_id']}"
                    if artifacts:
                        result["report_hash"] = _get_hash(result["report_link"])
                elif file["file_label"] == "CC Certificate":
                    result["cert_link"] = constants.CC_USA_GETFILE_URL + f"?file_id={file['file_id']}"
                    if artifacts:
                        result["cert_hash"] = _get_hash(result["cert_link"])
                elif file["file_label"] == "Security Target":
                    result["target_link"] = constants.CC_USA_GETFILE_URL + f"?file_id={file['file_id']}"
                    if artifacts:
                        result["target_hash"] = _get_hash(result["target_link"])
                elif file["file_label"] == "Assurance Activity Report (AAR)":
                    result["aar_link"] = constants.CC_USA_GETFILE_URL + f"?file_id={file['file_id']}"
                    if artifacts:
                        result["aar_hash"] = _get_hash(result["aar_link"])
                elif file["file_label"] == "Administrative Guide (AGD)":
                    result["agd_link"] = constants.CC_USA_GETFILE_URL + f"?file_id={file['file_id']}"
                    if artifacts:
                        result["agd_hash"] = _get_hash(result["agd_link"])

        return result

    session = requests.Session()
    results = []
    offset = 0
    got = 0
    pbar = tqdm(desc=f"Get US scheme {name}.")
    while True:
        resp = _getq(
            constants.CC_USA_PRODUCTS_URL,
            {"limit": 100, "offset": offset, **args},
            session,
        )
        json = resp.json()
        count = json["count"]
        for cert in json["results"]["products"]:
            got += 1
            if "from_cc_portal" in cert:
                continue
            files = None
            if enhanced:
                resp = _getq(
                    constants.CC_USA_FILES_URL,
                    {"product_id": cert["product_id"]},
                    session,
                )
                files = resp.json()
            pbar.update()
            results.append(map_cert(cert, files))
        offset += 100
        if got >= count:
            break
    pbar.close()
    return results


def get_usa_certified(  # noqa: C901
    enhanced: bool = True, artifacts: bool = False
) -> list[dict[str, Any]]:
    """
    Get American "certified product" entries.

    :param enhanced: Whether to enhance the results by following links (slower, more data).
    :param artifacts: Whether to download and compute artifact hashes (way slower, even more data).
    :return: The entries.
    """
    return _get_usa(
        {"certification_status": "Certified", "publish_status": "Published"}, enhanced, artifacts, "certified"
    )


def get_usa_in_evaluation() -> list[dict[str, Any]]:
    """
    Get American "product in evaluation" entries.

    :return: The entries.
    """
    return _get_usa({"status": "In Progress", "publish_status": "Published"}, False, False, "in evaluation")


def get_usa_archived() -> list[dict[str, Any]]:
    """
    Get American "archived product" entries.

    :return: The entries.
    """
    return _get_usa({"status": "Archived", "publish_status": "Published"}, False, False, "archived")


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
        "CA": {
            EntryType.InEvaluation: get_canada_in_evaluation,
            EntryType.Certified: get_canada_certified,
        },
        "FR": {
            EntryType.Certified: get_france_certified,
            EntryType.Archived: get_france_archived,
        },
        "DE": {EntryType.Certified: get_germany_certified},
        "IN": {
            EntryType.Certified: get_india_certified,
            EntryType.Archived: get_india_archived,
        },
        "IT": {
            EntryType.Certified: get_italy_certified,
            EntryType.InEvaluation: get_italy_in_evaluation,
        },
        "JP": {
            EntryType.InEvaluation: get_japan_in_evaluation,
            EntryType.Certified: get_japan_certified,
            EntryType.Archived: get_japan_archived,
        },
        "MY": {
            EntryType.Certified: get_malaysia_certified,
            EntryType.Archived: get_malaysia_archived,
            EntryType.InEvaluation: get_malaysia_in_evaluation,
        },
        "NL": {
            EntryType.Certified: get_netherlands_certified,
            EntryType.InEvaluation: get_netherlands_in_evaluation,
        },
        "NO": {
            EntryType.Certified: get_norway_certified,
            EntryType.Archived: get_norway_archived,
        },
        "KR": {
            EntryType.Certified: get_korea_certified,
            EntryType.Archived: get_korea_archived,
        },
        "PL": {
            EntryType.Certified: get_poland_certified,
            EntryType.InEvaluation: get_poland_ineval,
        },
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
        def _deserialize_entry(entry):
            if isinstance(entry, dict):
                res = {}
                for key, value in entry.items():
                    if key.endswith("_date"):
                        res[key] = date.fromisoformat(value) if value is not None else None
                    else:
                        res[key] = _deserialize_entry(value)
                return res
            elif isinstance(entry, list):
                return list(map(_deserialize_entry, entry))
            else:
                return entry

        return cls(
            dct["country"],
            datetime.fromisoformat(dct["timestamp"]),
            {EntryType(entry_type): _deserialize_entry(entries) for entry_type, entries in dct["lists"].items()},
        )

    def to_dict(self):
        return {
            "country": self.country,
            "timestamp": self.timestamp.isoformat(),
            "lists": {entry_type.value: entries for entry_type, entries in self.lists.items()},
        }

    @classmethod
    def from_web(
        cls, scheme: str, entry_types: Iterable[EntryType], enhanced: bool | None = None, artifacts: bool | None = None
    ) -> CCScheme:
        if not (scheme_lists := cls.methods.get(scheme)):
            raise ValueError("Unknown scheme.")
        entries = {}
        timestamp = datetime.now()
        for each_type in entry_types:
            if not (method := scheme_lists.get(each_type)):
                raise ValueError("Wrong entry_type for scheme.")
            sig = signature(method)
            args = {}
            if enhanced is not None and "enhanced" in sig.parameters:
                args["enhanced"] = enhanced
            if artifacts is not None and "artifacts" in sig.parameters:
                args["artifacts"] = artifacts
            entries[each_type] = method(**args)
        return cls(scheme, timestamp, entries)
