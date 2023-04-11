import tempfile
from pathlib import Path

import requests
import tabula
from bs4 import BeautifulSoup, NavigableString

from sec_certs import constants
from sec_certs.utils.sanitization import sanitize_navigable_string as sns


class CCSchemeDataset:
    @staticmethod
    def _download_page(url, session=None):
        conn = session if session else requests
        resp = conn.get(url, headers={"User-Agent": "seccerts.org"}, verify=False)
        if resp.status_code != requests.codes.ok:
            raise ValueError(f"Unable to download: status={resp.status_code}")
        return BeautifulSoup(resp.content, "html5lib")

    @staticmethod
    def get_australia_in_evaluation():
        # TODO: Information could be expanded by following url.
        soup = CCSchemeDataset._download_page(constants.CC_AUSTRALIA_CERTIFIED_URL)
        header = soup.find("h2", text="Products in evaluation")
        table = header.find_next_sibling("table")
        results = []
        for tr in table.find_all("tr"):
            tds = tr.find_all("td")
            if not tds:
                continue
            cert = {
                "vendor": sns(tds[0].text),
                "product": sns(tds[1].text),
                "url": constants.CC_AUSTRALIA_BASE_URL + tds[1].find("a")["href"],
                "level": sns(tds[2].text),
            }
            results.append(cert)
        return results

    @staticmethod
    def get_canada_certified():
        soup = CCSchemeDataset._download_page(constants.CC_CANADA_CERTIFIED_URL)
        tbody = soup.find("table").find("tbody")
        results = []
        for tr in tbody.find_all("tr"):
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
        soup = CCSchemeDataset._download_page(constants.CC_CANADA_INEVAL_URL)
        tbody = soup.find("table").find("tbody")
        results = []
        for tr in tbody.find_all("tr"):
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
    def get_france_certified():
        # TODO: Information could be expanded by following product link.
        base_soup = CCSchemeDataset._download_page(constants.CC_ANSSI_CERTIFIED_URL)
        category_nav = base_soup.find("ul", class_="nav-categories")
        results = []
        for li in category_nav.find_all("li"):
            a = li.find("a")
            url = a["href"]
            category_name = sns(a.text)
            soup = CCSchemeDataset._download_page(constants.CC_ANSSI_BASE_URL + url)
            table = soup.find("table", class_="produits-liste cc")
            if not table:
                continue
            tbody = table.find("tbody")
            for tr in tbody.find_all("tr"):
                tds = tr.find_all("td")
                if not tds:
                    continue
                cert = {
                    "product": sns(tds[0].text),
                    "vendor": sns(tds[1].text),
                    "level": sns(tds[2].text),
                    "id": sns(tds[3].text),
                    "certification_date": sns(tds[4].text),
                    "category": category_name,
                    "url": constants.CC_ANSSI_BASE_URL + tds[0].find("a")["href"],
                }
                results.append(cert)
        return results

    @staticmethod
    def get_germany_certified():
        # TODO: Information could be expanded by following url.
        base_soup = CCSchemeDataset._download_page(constants.CC_BSI_CERTIFIED_URL)
        category_nav = base_soup.find("ul", class_="no-bullet row")
        results = []
        for li in category_nav.find_all("li"):
            a = li.find("a")
            url = a["href"]
            category_name = sns(a.text)
            soup = CCSchemeDataset._download_page(constants.CC_BSI_BASE_URL + url)
            content = soup.find("div", class_="content").find("div", class_="column")
            for table in content.find_all("table"):
                tbody = table.find("tbody")
                header = table.find_parent("div", class_="wrapperTable").find_previous_sibling("h2")
                for tr in tbody.find_all("tr"):
                    tds = tr.find_all("td")
                    if len(tds) != 4:
                        continue
                    cert = {
                        "cert_id": sns(tds[0].text),
                        "product": sns(tds[1].text),
                        "vendor": sns(tds[2].text),
                        "certification_date": sns(tds[3].text),
                        "category": category_name,
                        "url": constants.CC_BSI_BASE_URL + tds[0].find("a")["href"],
                    }
                    if header is not None:
                        cert["subcategory"] = sns(header.text)
                    results.append(cert)
        return results

    @staticmethod
    def get_india_certified():
        pages = {0}
        seen_pages = set()
        results = []
        while pages:
            page = pages.pop()
            seen_pages.add(page)
            url = constants.CC_INDIA_CERTIFIED_URL + f"?page={page}"
            soup = CCSchemeDataset._download_page(url)

            # Update pages
            pager = soup.find("ul", class_="pager")
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
                    "report_link": report_a["href"],
                    "report_name": sns(report_a.text),
                    "target_link": target_a["href"],
                    "target_name": sns(target_a.text),
                    "cert_link": cert_a["href"],
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
            soup = CCSchemeDataset._download_page(url)

            # Update pages
            pager = soup.find("ul", class_="pager")
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
                    "report_link": report_a["href"],
                    "report_name": sns(report_a.text),
                    "target_link": target_a["href"],
                    "target_name": sns(target_a.text),
                    "cert_link": cert_a["href"],
                    "cert_name": sns(cert_a.text),
                    "certification_date": sns(tds[8].text),
                }
                results.append(cert)
        return results

    @staticmethod
    def get_italy_certified():  # noqa: C901
        soup = CCSchemeDataset._download_page(constants.CC_ITALY_CERTIFIED_URL)
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
                    cert["report_link_it"] = constants.CC_ITALY_BASE_URL + p_link["href"]
                elif "Certification Report" in p_name and p_link:
                    cert["report_link_en"] = constants.CC_ITALY_BASE_URL + p_link["href"]
                elif "Traguardo di Sicurezza" in p_name and p_link:
                    cert["target_link"] = constants.CC_ITALY_BASE_URL + p_link["href"]
                elif "Nota su" in p_name and p_link:
                    cert["vulnerability_note_link"] = constants.CC_ITALY_BASE_URL + p_link["href"]
                elif "Nota di chiarimento" in p_name and p_link:
                    cert["clarification_note_link"] = constants.CC_ITALY_BASE_URL + p_link["href"]
            results.append(cert)
        return results

    @staticmethod
    def get_italy_in_evaluation():
        soup = CCSchemeDataset._download_page(constants.CC_ITALY_INEVAL_URL)
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
    def get_japan_certified():
        # TODO: Information could be expanded by following toe link.
        soup = CCSchemeDataset._download_page(constants.CC_JAPAN_CERTIFIED_URL)
        table = soup.find("div", id="cert_list").find("table")
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
                    cert["toe_overseas_link"] = constants.CC_JAPAN_CERT_BASE_URL + "/" + toe_a["href"]
                results.append(cert)
            if len(tds) == 1:
                cert = results[-1]
                cert["toe_japan_name"] = sns(tds[0].text)
                toe_a = tds[0].find("a")
                if toe_a and "href" in toe_a.attrs:
                    cert["toe_japan_link"] = constants.CC_JAPAN_CERT_BASE_URL + "/" + toe_a["href"]
        return results

    @staticmethod
    def get_japan_archived():
        # TODO: Information could be expanded by following toe link.
        soup = CCSchemeDataset._download_page(constants.CC_JAPAN_ARCHIVED_URL)
        table = soup.find("table")
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
                    cert["toe_overseas_link"] = constants.CC_JAPAN_CERT_BASE_URL + "/" + toe_a["href"]
                results.append(cert)
            if len(tds) == 1:
                cert = results[-1]
                cert["toe_japan_name"] = sns(tds[0].text)
                toe_a = tds[0].find("a")
                if toe_a and "href" in toe_a.attrs:
                    cert["toe_japan_link"] = constants.CC_JAPAN_CERT_BASE_URL + "/" + toe_a["href"]
        return results

    @staticmethod
    def get_japan_in_evaluation():
        # TODO: Information could be expanded by following toe link.
        soup = CCSchemeDataset._download_page(constants.CC_JAPAN_INEVAL_URL)
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
                "toe_link": constants.CC_JAPAN_BASE_URL + "/" + toe_a["href"],
                "claim": sns(tds[2].text),
            }
            results.append(cert)
        return results

    @staticmethod
    def get_malaysia_certified():
        soup = CCSchemeDataset._download_page(constants.CC_MALAYSIA_CERTIFIED_URL)
        main_div = soup.find("div", attrs={"itemprop": "articleBody"})
        tables = main_div.find_all("table", recursive=False)
        results = []
        for table in tables:
            category_name = sns(table.find_previous_sibling("h3").text)
            for tr in table.find_all("tr")[1:]:
                tds = tr.find_all("td")
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
        soup = CCSchemeDataset._download_page(constants.CC_MALAYSIA_INEVAL_URL)
        main_div = soup.find("div", attrs={"itemprop": "articleBody"})
        tables = main_div.find_all("table", recursive=False)
        results = []
        for table in tables:
            category_name = sns(table.find_previous_sibling("h3").text)
            for tr in table.find_all("tr")[1:]:
                tds = tr.find_all("td")
                if len(tds) != 5:
                    continue
                cert = {
                    "category": category_name,
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
        soup = CCSchemeDataset._download_page(constants.CC_NETHERLANDS_CERTIFIED_URL)
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
                    cert["cert_link"] = constants.CC_NETHERLANDS_BASE_URL + td.find("a")["href"]
                elif "Certificationreport" in th_text:
                    cert["report_link"] = constants.CC_NETHERLANDS_BASE_URL + td.find("a")["href"]
                elif "Securitytarget" in th_text:
                    cert["target_link"] = constants.CC_NETHERLANDS_BASE_URL + td.find("a")["href"]
                elif "Maintenance report" in th_text:
                    cert["maintenance_link"] = constants.CC_NETHERLANDS_BASE_URL + td.find("a")["href"]
            results.append(cert)
        return results

    @staticmethod
    def get_netherlands_in_evaluation():
        soup = CCSchemeDataset._download_page(constants.CC_NETHERLANDS_INEVAL_URL)
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
    def _get_norway(url):
        # TODO: Information could be expanded by following product link.
        soup = CCSchemeDataset._download_page(url)
        results = []
        for tr in soup.find_all("tr", class_="certified-product"):
            tds = tr.find_all("td")
            cert = {
                "product": sns(tds[0].text),
                "product_link": tds[0].find("a")["href"],
                "category": sns(tds[1].find("p", class_="value").text),
                "developer": sns(tds[2].find("p", class_="value").text),
                "certification_date": sns(tds[3].find("time").text),
            }
            results.append(cert)
        return results

    @staticmethod
    def get_norway_certified():
        return CCSchemeDataset._get_norway(constants.CC_NORWAY_CERTIFIED_URL)

    @staticmethod
    def get_norway_archived():
        return CCSchemeDataset._get_norway(constants.CC_NORWAY_ARCHIVED_URL)

    @staticmethod
    def _get_korea(product_class):
        # TODO: Information could be expanded by following product link.
        session = requests.session()
        session.get(constants.CC_KOREA_EN_URL)
        # Get base page
        url = constants.CC_KOREA_CERTIFIED_URL + f"?product_class={product_class}"
        soup = CCSchemeDataset._download_page(url, session=session)
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
        soup = CCSchemeDataset._download_page(url)
        table = soup.find("table")
        skip = False
        results = []
        category_name = None
        for tr in table.find_all("tr"):
            if skip:
                skip = False
                continue
            tds = tr.find_all("td")
            if len(tds) == 1:
                category_name = sns(tds[0].text)
                skip = True
                continue

            cert = {
                "product": sns(tds[0].text.split()[0]),
                "vendor": sns(tds[1].text),
                "level": sns(tds[2].text),
                "certification_date": sns(tds[3].text),
                "expiration_date": sns(tds[4].text),
                "category": category_name,
            }
            for link in tds[0].find_all("a"):
                link_text = sns(link.text)
                if link_text == "Certificate":
                    cert["cert_link"] = constants.CC_SINGAPORE_BASE_URL + link["href"]
                elif link_text in ("Certificate Report", "Certification Report"):
                    cert["report_link"] = constants.CC_SINGAPORE_BASE_URL + link["href"]
                elif link_text == "Security Target":
                    cert["target_link"] = constants.CC_SINGAPORE_BASE_URL + link["href"]
            results.append(cert)
        return results

    @staticmethod
    def get_singapore_certified():
        return CCSchemeDataset._get_singapore(constants.CC_SINGAPORE_CERTIFIED_URL)

    @staticmethod
    def get_singapore_in_evaluation():
        soup = CCSchemeDataset._download_page(constants.CC_SINGAPORE_CERTIFIED_URL)
        header = soup.find(lambda x: x.name == "h3" and x.text == "In Evaluation")
        table = header.find_next("table")
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
        soup = CCSchemeDataset._download_page(constants.CC_SPAIN_CERTIFIED_URL)
        tbody = soup.find("table", class_="djc_items_table").find("tbody")
        results = []
        for tr in tbody.find_all("tr", recursive=False):
            tds = tr.find_all("td")
            cert = {
                "product": sns(tds[0].text),
                "product_link": constants.CC_SPAIN_BASE_URL + tds[0].find("a")["href"],
                "category": sns(tds[1].text),
                "manufacturer": sns(tds[2].text),
                "certification_date": sns(tds[3].find("td", class_="djc_value").text),
            }
            results.append(cert)
        return results

    @staticmethod
    def _get_sweden(url):
        # TODO: Information could be expanded by following product link.
        soup = CCSchemeDataset._download_page(url)
        nav = soup.find("main").find("nav", class_="component-nav-box__list")
        results = []
        for link in nav.find_all("a"):
            cert = {"product": sns(link.text), "product_link": constants.CC_SWEDEN_BASE_URL + link["href"]}
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
        soup = CCSchemeDataset._download_page(constants.CC_USA_CERTIFIED_URL)
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
                "product_link": product_link["href"],
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
        soup = CCSchemeDataset._download_page(constants.CC_USA_INEVAL_URL)
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
        soup = CCSchemeDataset._download_page(constants.CC_USA_ARCHIVED_URL)
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
