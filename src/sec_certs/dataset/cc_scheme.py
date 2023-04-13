from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
import tabula
from bs4 import BeautifulSoup, NavigableString, Tag
from requests import Response

from sec_certs import constants
from sec_certs.utils.sanitization import sanitize_navigable_string as sns
from sec_certs.utils.tqdm import tqdm


class CCSchemeDataset:
    @staticmethod
    def _get(url: str, session, **kwargs) -> Response:
        conn = session if session else requests
        resp = conn.get(url, headers={"User-Agent": "seccerts.org"}, verify=False, **kwargs)
        resp.raise_for_status()
        return resp

    @staticmethod
    def _get_page(url: str, session=None) -> BeautifulSoup:
        return BeautifulSoup(CCSchemeDataset._get(url, session).content, "html5lib")

    @staticmethod
    def _get_hash(url: str, session=None) -> bytes:
        resp = CCSchemeDataset._get(url, session)
        h = hashlib.sha256()
        for chunk in resp.iter_content():
            h.update(chunk)
        return h.digest()

    @staticmethod
    def get_australia_in_evaluation(enhanced: bool = True):  # noqa: C901
        soup = CCSchemeDataset._get_page(constants.CC_AUSTRALIA_INEVAL_URL)
        header = soup.find("h2", text="Products in evaluation")
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
                cert_page = CCSchemeDataset._get_page(cert["url"])
                article = cert_page.find("article", attrs={"role": "article"})
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

    @staticmethod
    def get_canada_certified():
        soup = CCSchemeDataset._get_page(constants.CC_CANADA_CERTIFIED_URL)
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

    @staticmethod
    def get_canada_in_evaluation():
        soup = CCSchemeDataset._get_page(constants.CC_CANADA_INEVAL_URL)
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

    @staticmethod
    def get_france_certified(enhanced: bool = True, artifacts: bool = False):  # noqa: C901
        base_soup = CCSchemeDataset._get_page(constants.CC_ANSSI_CERTIFIED_URL)
        category_nav = base_soup.find("ul", class_="nav-categories")
        results = []
        for li in tqdm(category_nav.find_all("li"), desc="Get FR scheme certified."):
            a = li.find("a")
            url = a["href"]
            category_name = sns(a.text)
            soup = CCSchemeDataset._get_page(urljoin(constants.CC_ANSSI_BASE_URL, url))
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
                    cert_page = CCSchemeDataset._get_page(cert["url"])
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
                                e["report_hash"] = CCSchemeDataset._get_hash(href).hex()
                        elif "Security target" in title:
                            e["target_link"] = href
                            if artifacts:
                                e["target_hash"] = CCSchemeDataset._get_hash(href).hex()
                        elif "Certificat" in title:
                            e["cert_link"] = href
                            if artifacts:
                                e["cert_hash"] = CCSchemeDataset._get_hash(href).hex()
                    cert["enhanced"] = e
                results.append(cert)
        return results

    @staticmethod
    def get_germany_certified(enhanced: bool = True, artifacts: bool = False):  # noqa: C901
        """ """
        base_soup = CCSchemeDataset._get_page(constants.CC_BSI_CERTIFIED_URL)
        category_nav = base_soup.find("ul", class_="no-bullet row")
        results = []
        for li in tqdm(category_nav.find_all("li"), desc="Get DE scheme certified."):
            a = li.find("a")
            url = a["href"]
            category_name = sns(a.text)
            soup = CCSchemeDataset._get_page(urljoin(constants.CC_BSI_BASE_URL, url))
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
                        cert_page = CCSchemeDataset._get_page(cert["url"])
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
                                    e["report_hash"] = CCSchemeDataset._get_hash(href).hex()
                            elif "Security Target" in title:
                                e["target_link"] = href
                                if artifacts:
                                    e["target_hash"] = CCSchemeDataset._get_hash(href).hex()
                            elif "Certificate" in title:
                                e["cert_link"] = href
                                if artifacts:
                                    e["cert_hash"] = CCSchemeDataset._get_hash(href).hex()
                        description = content.find("div", attrs={"lang": "en"})
                        if description:
                            e["description"] = sns(description.text)
                        cert["enhanced"] = e
                    if header is not None:
                        cert["subcategory"] = sns(header.text)
                    results.append(cert)
        return results

    @staticmethod
    def _fix_india_link(link):
        return link.replace("/index.php", "")

    @staticmethod
    def get_india_certified():
        pages = {0}
        seen_pages = set()
        results = []
        while pages:
            page = pages.pop()
            seen_pages.add(page)
            url = constants.CC_INDIA_CERTIFIED_URL + f"?page={page}"
            soup = CCSchemeDataset._get_page(url)

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
                    "report_link": urljoin(
                        constants.CC_INDIA_BASE_URL, CCSchemeDataset._fix_india_link(report_a["href"])
                    ),
                    "report_name": sns(report_a.text),
                    "target_link": urljoin(
                        constants.CC_INDIA_BASE_URL, CCSchemeDataset._fix_india_link(target_a["href"])
                    ),
                    "target_name": sns(target_a.text),
                    "cert_link": urljoin(constants.CC_INDIA_BASE_URL, CCSchemeDataset._fix_india_link(cert_a["href"])),
                    "cert_name": sns(cert_a.text),
                }
                results.append(cert)
        return results

    @staticmethod
    def get_india_archived():
        pages = {0}
        seen_pages = set()
        results = []
        while pages:
            page = pages.pop()
            seen_pages.add(page)
            url = constants.CC_INDIA_ARCHIVED_URL + f"?page={page}"
            soup = CCSchemeDataset._get_page(url)

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
                    "target_link": urljoin(
                        constants.CC_INDIA_BASE_URL, CCSchemeDataset._fix_india_link(target_a["href"])
                    ),
                    "target_name": sns(target_a.text),
                    "cert_link": urljoin(constants.CC_INDIA_BASE_URL, CCSchemeDataset._fix_india_link(cert_a["href"])),
                    "cert_name": sns(cert_a.text),
                    "certification_date": sns(tds[8].text),
                }
                if report_a:
                    cert["report_link"] = urljoin(
                        constants.CC_INDIA_BASE_URL, CCSchemeDataset._fix_india_link(report_a["href"])
                    )
                    cert["report_name"] = sns(report_a.text)
                results.append(cert)
        return results

    @staticmethod
    def get_italy_certified():  # noqa: C901
        soup = CCSchemeDataset._get_page(constants.CC_ITALY_CERTIFIED_URL)
        div = soup.find("div", class_="certificati")
        results = []
        for cert_div in div.find_all("div", recursive=False):
            title = cert_div.find("h3").text
            data_div = cert_div.find("div", class_="collapse")
            cert = {"title": title}
            for data_p in data_div.find_all("p"):
                p_text = sns(data_p.text)
                if ":" not in p_text:
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

    @staticmethod
    def get_italy_in_evaluation():
        soup = CCSchemeDataset._get_page(constants.CC_ITALY_INEVAL_URL)
        div = soup.find("div", class_="valutazioni")
        results = []
        for cert_div in div.find_all("div", recursive=False):
            title = cert_div.find("h3").text
            data_div = cert_div.find("div", class_="collapse")
            cert = {"title": title}
            for data_p in data_div.find_all("p"):
                p_text = sns(data_p.text)
                if ":" not in p_text:
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

    @staticmethod
    def _get_japan(url):
        # TODO: Information could be expanded by following toe link.
        soup = CCSchemeDataset._get_page(url)
        table = soup.find("table", class_="cert-table")
        results = []
        trs = list(table.find_all("tr"))
        for tr in trs:
            tds = tr.find_all("td")
            if not tds:
                continue
            if len(tds) == 6:
                cert = {
                    "cert_id": sns(tds[0].text),
                    "supplier": sns(tds[1].text),
                    "toe_overseas_name": sns(tds[2].text),
                    "certification_date": sns(tds[3].text),
                    "claim": sns(tds[4].text),
                }
                toe_a = tds[2].find("a")
                if toe_a and "href" in toe_a.attrs:
                    cert["toe_overseas_link"] = urljoin(constants.CC_JAPAN_CERT_BASE_URL, "/" + toe_a["href"])
                results.append(cert)
            if len(tds) == 1:
                cert = results[-1]
                cert["toe_japan_name"] = sns(tds[0].text)
                toe_a = tds[0].find("a")
                if toe_a and "href" in toe_a.attrs:
                    cert["toe_japan_link"] = urljoin(constants.CC_JAPAN_CERT_BASE_URL, "/" + toe_a["href"])
        return results

    @staticmethod
    def get_japan_certified():
        japan_hw = CCSchemeDataset._get_japan(constants.CC_JAPAN_CERTIFIED_HW_URL)
        japan_sw = CCSchemeDataset._get_japan(constants.CC_JAPAN_CERTIFIED_SW_URL)
        return japan_sw + japan_hw

    @staticmethod
    def get_japan_archived():
        return CCSchemeDataset._get_japan(constants.CC_JAPAN_ARCHIVED_SW_URL)

    @staticmethod
    def get_japan_in_evaluation():
        # TODO: Information could be expanded by following toe link.
        soup = CCSchemeDataset._get_page(constants.CC_JAPAN_INEVAL_URL)
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
                "toe_link": urljoin(constants.CC_JAPAN_BASE_URL, "/" + toe_a["href"]),
                "claim": sns(tds[2].text),
            }
            results.append(cert)
        return results

    @staticmethod
    def get_malaysia_certified():
        soup = CCSchemeDataset._get_page(constants.CC_MALAYSIA_CERTIFIED_URL)
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

    @staticmethod
    def get_malaysia_in_evaluation():
        soup = CCSchemeDataset._get_page(constants.CC_MALAYSIA_INEVAL_URL)
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

    @staticmethod
    def get_netherlands_certified():
        soup = CCSchemeDataset._get_page(constants.CC_NETHERLANDS_CERTIFIED_URL)
        main_div = soup.select("body > main > div > div > div > div:nth-child(2) > div.col-lg-9 > div:nth-child(3)")[0]
        rows = main_div.find_all("div", class_="row", recursive=False)
        modals = main_div.find_all("div", class_="modal", recursive=False)
        results = []
        for row, modal in zip(rows, modals):
            row_entries = row.find_all("a")
            modal_trs = modal.find_all("tr")
            cert = {
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
                elif "Certificationreport" in th_text:
                    cert["report_link"] = urljoin(constants.CC_NETHERLANDS_BASE_URL, td.find("a")["href"])
                elif "Securitytarget" in th_text:
                    cert["target_link"] = urljoin(constants.CC_NETHERLANDS_BASE_URL, td.find("a")["href"])
                elif "Maintenance report" in th_text:
                    cert["maintenance_link"] = urljoin(constants.CC_NETHERLANDS_BASE_URL, td.find("a")["href"])
            results.append(cert)
        return results

    @staticmethod
    def get_netherlands_in_evaluation():
        soup = CCSchemeDataset._get_page(constants.CC_NETHERLANDS_INEVAL_URL)
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

    @staticmethod
    def _get_norway(url: str, enhanced: bool, artifacts: bool):  # noqa: C901
        soup = CCSchemeDataset._get_page(url)
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
                cert_page = CCSchemeDataset._get_page(cert["url"])
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
                    if "Certificate No." in title:
                        e["id"] = value
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
                            entry["hash"] = CCSchemeDataset._get_hash(entry["href"]).hex()
                        entries.append(entry)
                    e["documents"][doc_type] = entries
                cert["enhanced"] = e
            results.append(cert)
        return results

    @staticmethod
    def get_norway_certified(enhanced: bool = True, artifacts: bool = False):
        return CCSchemeDataset._get_norway(constants.CC_NORWAY_CERTIFIED_URL, enhanced, artifacts)

    @staticmethod
    def get_norway_archived(enhanced: bool = True, artifacts: bool = False):
        return CCSchemeDataset._get_norway(constants.CC_NORWAY_ARCHIVED_URL, enhanced, artifacts)

    @staticmethod
    def _get_korea(product_class):
        # TODO: Information could be expanded by following product link.
        session = requests.session()
        session.get(constants.CC_KOREA_EN_URL)
        # Get base page
        url = constants.CC_KOREA_CERTIFIED_URL + f"?product_class={product_class}"
        soup = CCSchemeDataset._get_page(url, session=session)
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
                cert = {
                    "product": sns(tds[0].text),
                    "cert_id": sns(tds[1].text),
                    "product_link": constants.CC_KOREA_PRODUCT_URL.format(id),
                    "vendor": sns(tds[2].text),
                    "level": sns(tds[3].text),
                    "category": sns(tds[4].text),
                    "certification_date": sns(tds[5].text),
                }
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

    @staticmethod
    def get_korea_certified():
        return CCSchemeDataset._get_korea(product_class=1)

    @staticmethod
    def get_korea_suspended():
        return CCSchemeDataset._get_korea(product_class=2)

    @staticmethod
    def get_korea_archived():
        return CCSchemeDataset._get_korea(product_class=4)

    @staticmethod
    def _get_singapore(url):
        soup = CCSchemeDataset._get_page(url)
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
        results = []
        while len(results) != total:
            for obj in api_json["objects"]:
                cert = {
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

    @staticmethod
    def get_singapore_certified():
        return CCSchemeDataset._get_singapore(constants.CC_SINGAPORE_CERTIFIED_URL)

    @staticmethod
    def get_singapore_in_evaluation():
        soup = CCSchemeDataset._get_page(constants.CC_SINGAPORE_INEVAL_URL)
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

    @staticmethod
    def get_singapore_archived():
        return CCSchemeDataset._get_singapore(constants.CC_SINGAPORE_ARCHIVED_URL)

    @staticmethod
    def get_spain_certified():
        soup = CCSchemeDataset._get_page(constants.CC_SPAIN_CERTIFIED_URL)
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

    @staticmethod
    def _get_sweden(url):
        # TODO: Information could be expanded by following product link.
        soup = CCSchemeDataset._get_page(url)
        nav = soup.find("main").find("nav", class_="component-nav-box__list")
        results = []
        for link in nav.find_all("a"):
            cert = {"product": sns(link.text), "product_link": urljoin(constants.CC_SWEDEN_BASE_URL, link["href"])}
            results.append(cert)
        return results

    @staticmethod
    def get_sweden_certified():
        return CCSchemeDataset._get_sweden(constants.CC_SWEDEN_CERTIFIED_URL)

    @staticmethod
    def get_sweden_in_evaluation():
        return CCSchemeDataset._get_sweden(constants.CC_SWEDEN_INEVAL_URL)

    @staticmethod
    def get_sweden_archived():
        return CCSchemeDataset._get_sweden(constants.CC_SWEDEN_ARCHIVED_URL)

    @staticmethod
    def get_turkey_certified():
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
                for line in df.values:
                    cert = {
                        # TODO: Split item number and generate several dicts for a range they include.
                        "item_no": line[0],
                        "developer": line[1],
                        "product": line[2],
                        "cc_version": line[3],
                        "level": line[4],
                        "cert_lab": line[5],
                        "certification_date": line[6],
                        "expiration_date": line[7],
                        # TODO: Parse "Ongoing Evaluation" out of this field as well.
                        "archived": isinstance(line[9], str) and "Archived" in line[9],
                    }
                    results.append(cert)
        return results

    @staticmethod
    def get_usa_certified():
        # TODO: Information could be expanded by following product link.
        # TODO: Information could be expanded by following the cc_claims (has links to protection profiles).
        soup = CCSchemeDataset._get_page(constants.CC_USA_CERTIFIED_URL)
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
            cert = {
                "product": sns(product_link.text),
                "vendor": sns(vendor_span.text),
                "product_link": urljoin(constants.CC_USA_PRODUCT_URL, product_link["href"]),
                "id": sns(tds[1].text),
                "cc_claim": sns(tds[2].text),
                "cert_lab": sns(tds[3].text),
                "certification_date": sns(tds[4].text),
                "assurance_maintenance_date": sns(tds[5].text),
            }
            results.append(cert)
        return results

    @staticmethod
    def get_usa_in_evaluation():
        # TODO: Information could be expanded by following the cc_claims (has links to protection profiles).
        soup = CCSchemeDataset._get_page(constants.CC_USA_INEVAL_URL)
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

    @staticmethod
    def get_usa_archived():
        # TODO: Information could be expanded by following the cc_claims (has links to protection profiles).
        soup = CCSchemeDataset._get_page(constants.CC_USA_ARCHIVED_URL)
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
