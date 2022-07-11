from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple, Union

import requests
from bs4 import BeautifulSoup, NavigableString, Tag
from dateutil import parser
from tabula import read_pdf

import sec_certs.constants as constants
import sec_certs.utils.extract
import sec_certs.utils.helpers as helpers
import sec_certs.utils.pdf
import sec_certs.utils.tables
from sec_certs.cert_rules import fips_rules
from sec_certs.config.configuration import config
from sec_certs.sample.certificate import Certificate
from sec_certs.sample.certificate import Heuristics as BaseHeuristics
from sec_certs.sample.certificate import References, logger
from sec_certs.sample.cpe import CPE
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils.helpers import fips_dgst


class FIPSCertificate(Certificate["FIPSCertificate", "FIPSCertificate.Heuristics"], ComplexSerializableType):
    """
    Data structure for common FIPS 140 certificate. Contains several inner classes that layer the data logic.
    Can be serialized into/from json (`ComplexSerializableType`).
    Is basic element of `FIPSDataset`. The functionality is mostly related to holding data and transformations that
    the certificate can handle itself. `FIPSDataset` class then instrument this functionality.
    """

    @dataclass(eq=True)
    # TODO: Include sp_pdf_hash and sp_txt_hash.
    class InternalState(ComplexSerializableType):
        """
        Holds state of the `FIPSCertificate`
        """

        sp_path: Path
        html_path: Path
        tables_done: bool
        file_status: Optional[bool]
        txt_state: bool

        def __init__(
            self,
            sp_path: Union[str, Path],
            html_path: Union[str, Path],
            tables_done: bool,
            file_status: Optional[bool],
            txt_state: bool,
        ):
            self.sp_path = Path(sp_path)
            self.html_path = Path(html_path)
            self.tables_done = tables_done
            self.file_status = file_status
            self.txt_state = txt_state

    def set_local_paths(
        self,
        sp_dir: Optional[Union[str, Path]],
        html_dir: Optional[Union[str, Path]],
    ) -> None:
        if sp_dir is not None:
            self.state.sp_path = (Path(sp_dir) / (str(self.cert_id))).with_suffix(".pdf")
        if html_dir is not None:
            self.state.html_path = (Path(html_dir) / (str(self.cert_id))).with_suffix(".html")

    @dataclass(eq=True)
    class WebData(ComplexSerializableType):
        """
        Data structure for data obtained from scanning certificate webpage at NIST.gov
        """

        module_name: Optional[str]
        standard: Optional[str]
        status: Optional[str]
        date_sunset: Optional[datetime]
        date_validation: Optional[List[datetime]]
        level: Optional[str]
        caveat: Optional[str]
        exceptions: Optional[List[str]]
        module_type: Optional[str]
        embodiment: Optional[str]
        algorithms: Optional[List[Dict[str, str]]]
        tested_conf: Optional[List[str]]
        description: Optional[str]
        mentioned_certs: Optional[Dict[str, Dict[str, int]]]
        vendor: Optional[str]
        vendor_www: Optional[str]
        lab: Optional[str]
        lab_nvlap: Optional[str]
        historical_reason: Optional[str]
        security_policy_www: Optional[str]
        certificate_www: Optional[str]
        hw_version: Optional[str]
        fw_version: Optional[str]
        revoked_reason: Optional[str]
        revoked_link: Optional[str]
        sw_versions: Optional[str]
        product_url: Optional[str]

        @property
        def dgst(self) -> str:
            return helpers.get_first_16_bytes_sha256(
                self.product_url
                if self.product_url is not None
                else "" + self.vendor_www
                if self.vendor_www is not None
                else ""
            )

        def __repr__(self) -> str:
            return (
                self.module_name
                if self.module_name is not None
                else "" + " created by " + self.vendor
                if self.vendor is not None
                else ""
            )

        def __str__(self) -> str:
            return repr(self)

    @dataclass(eq=True)
    class PdfData(ComplexSerializableType):
        """
        Data structure that holds data obtained from scanning pdf files (or their converted txt documents).
        """

        cert_id: int
        keywords: Dict
        algorithms: List
        # TODO: Add metadata processing.

        @property
        def dgst(self) -> str:
            return helpers.get_first_16_bytes_sha256(str(self.keywords))

        def __repr__(self) -> str:
            return str(self.cert_id)

        def __str__(self) -> str:
            return str(self.cert_id)

    @dataclass(eq=True)
    class Heuristics(BaseHeuristics, ComplexSerializableType):
        """
        Data structure that holds data obtained by processing the certificate and applying various heuristics.
        """

        keywords: Dict[str, Dict]
        algorithms: List[Dict[str, Dict]]
        unmatched_algs: int

        extracted_versions: Optional[Set[str]] = field(default=None)
        cpe_matches: Optional[Set[str]] = field(default=None)
        verified_cpe_matches: Optional[Set[CPE]] = field(default=None)
        related_cves: Optional[Set[str]] = field(default=None)

        st_references: References = field(default_factory=References)
        web_references: References = field(default_factory=References)

        @property
        def serialized_attributes(self) -> List[str]:
            return copy.deepcopy(super().serialized_attributes)

        @property
        def dgst(self) -> str:
            return helpers.get_first_16_bytes_sha256(str(self.keywords))

    def __str__(self) -> str:
        return str(self.cert_id)

    @property
    def dgst(self) -> str:
        """
        Returns primary key of the certificate, its id.
        """
        return fips_dgst(self.cert_id)

    # TODO: Fix type errors, they exist because FIPS uses this as property to change variable names, while CC and abstract class have variables
    @property
    def manufacturer(self) -> Optional[str]:  # type: ignore
        return self.web_data.vendor

    @property
    def name(self) -> Optional[str]:  # type: ignore
        return self.web_data.module_name

    @property
    def label_studio_title(self) -> str:
        return (
            "Vendor: "
            + str(self.web_data.vendor)
            + "\n"
            + "Module name: "
            + str(self.web_data.module_name)
            + "\n"
            + "HW version: "
            + str(self.web_data.hw_version)
            + "\n"
            + "FW version: "
            + str(self.web_data.fw_version)
        )

    def __init__(
        self,
        cert_id: int,
        web_data: FIPSCertificate.WebData,
        pdf_data: FIPSCertificate.PdfData,
        heuristics: FIPSCertificate.Heuristics,
        state: InternalState,
    ):
        super().__init__()
        self.cert_id = cert_id
        self.web_data = web_data
        self.pdf_data = pdf_data
        self.heuristics = heuristics
        self.state = state

    @classmethod
    def from_dict(cls, dct: Dict) -> FIPSCertificate:
        """
        Deserializes dictionary into FIPSCertificate

        :param Dict dct: dictionary that holds the FIPSCertificate data
        :return FIPSCertificate: object reconstructed from dct
        """
        new_dct = dct.copy()

        if new_dct["web_data"].date_validation:
            new_dct["web_data"].date_validation = [parser.parse(x).date() for x in new_dct["web_data"].date_validation]

        if new_dct["web_data"].date_sunset:
            new_dct["web_data"].date_sunset = parser.parse(new_dct["web_data"].date_sunset).date()
        return super(cls, FIPSCertificate).from_dict(new_dct)

    @classmethod
    def from_html_file(
        cls, file: Path, state: InternalState, initialized: FIPSCertificate = None, redo: bool = False
    ) -> FIPSCertificate:
        """
        Constructs FIPSCertificate object from html file.

        :param Path file: path to the html file to use for initialization
        :param InternalState state: state of the certificate
        :param FIPSCertificate initialized: possibly partially initialized FIPSCertificate, defaults to None
        :param bool redo: if the method should be reattempted in case of failure, defaults to False
        :return FIPSCertificate: resulting `FIPSCertificate` object.
        """

        if not initialized:
            items_found = FIPSCertificate._initialize_dictionary()
            items_found["cert_id"] = int(file.stem)
        else:
            items_found = initialized.web_data.__dict__
            items_found["cert_id"] = initialized.cert_id
            items_found["revoked_reason"] = None
            items_found["revoked_link"] = None
            items_found["mentioned_certs"] = {}
            state.tables_done = initialized.state.tables_done
            state.file_status = initialized.state.file_status
            state.txt_state = initialized.state.txt_state

        if redo:
            items_found = FIPSCertificate._initialize_dictionary()
            items_found["cert_id"] = int(file.stem)

        text = sec_certs.utils.extract.load_cert_html_file(str(file))
        soup = BeautifulSoup(text, "html.parser")
        for div in soup.find_all("div", class_="row padrow"):
            FIPSCertificate._parse_html_main(div, items_found)

        for div in soup.find_all("div", class_="panel panel-default")[1:]:
            if div.find("h4", class_="panel-title").text == "Vendor":
                FIPSCertificate._parse_vendor(div, items_found, file)

            if div.find("h4", class_="panel-title").text == "Lab":
                FIPSCertificate._parse_lab(div, items_found, file)

            if div.find("h4", class_="panel-title").text == "Related Files":
                FIPSCertificate.parse_related_files(div, items_found)

            if div.find("h4", class_="panel-title").text == "Validation History":
                FIPSCertificate._parse_validation_dates(div, items_found)

        FIPSCertificate._normalize(items_found)

        return FIPSCertificate(
            items_found["cert_id"],
            FIPSCertificate.WebData(
                items_found["module_name"] if "module_name" in items_found else None,
                items_found["standard"] if "standard" in items_found else None,
                items_found["status"] if "status" in items_found else None,
                items_found["date_sunset"] if "date_sunset" in items_found else None,
                items_found["date_validation"] if "date_validation" in items_found else None,
                items_found["level"] if "level" in items_found else None,
                items_found["caveat"] if "caveat" in items_found else None,
                items_found["exceptions"] if "exceptions" in items_found else None,
                items_found["module_type"] if "module_type" in items_found else None,
                items_found["embodiment"] if "embodiment" in items_found else None,
                items_found["algorithms"] if "algorithms" in items_found else None,
                items_found["tested_conf"] if "tested_conf" in items_found else None,
                items_found["description"] if "description" in items_found else None,
                items_found["mentioned_certs"] if "mentioned_certs" in items_found else None,
                items_found["vendor"] if "vendor" in items_found else None,
                items_found["vendor_www"] if "vendor_www" in items_found else None,
                items_found["lab"] if "lab" in items_found else None,
                items_found["nvlap_code"] if "nvlap_code" in items_found else None,
                items_found["historical_reason"] if "historical_reason" in items_found else None,
                items_found["security_policy_www"] if "security_policy_www" in items_found else None,
                items_found["certificate_www"] if "certificate_www" in items_found else None,
                items_found["hw_versions"] if "hw_versions" in items_found else None,
                items_found["fw_versions"] if "fw_versions" in items_found else None,
                items_found["revoked_reason"] if "revoked_reason" in items_found else None,
                items_found["revoked_link"] if "revoked_link" in items_found else None,
                items_found["sw_versions"] if "sw_versions" in items_found else None,
                items_found["product_url"] if "product_url" in items_found else None,
            ),
            FIPSCertificate.PdfData(
                items_found["cert_id"],
                {} if not initialized else initialized.pdf_data.keywords,
                [] if not initialized else initialized.pdf_data.algorithms,
            ),
            FIPSCertificate.Heuristics(dict(), [], 0),
            state,
        )

    @staticmethod
    def download_html_page(cert: Tuple[str, Path]) -> Optional[Tuple[str, Path]]:
        """
        Wrapper for downloading a file. `delay=1` introduced to avoid problems with requests at NIST.gov

        :param Tuple[str, Path] cert: tuple url, output_path
        :return Optional[Tuple[str, Path]]: None on success, `cert` on failure.
        """
        exit_code = helpers.download_file(*cert, delay=constants.FIPS_DOWNLOAD_DELAY)
        if exit_code != requests.codes.ok:
            logger.error(f"Failed to download html page from {cert[0]}, code: {exit_code}")
            return cert
        return None

    @staticmethod
    def download_security_policy(cert: Tuple[str, Path]) -> None:
        """
        Downloads security policy file from web. Staticmethod to allow for parametrization.
        """
        exit_code = helpers.download_file(*cert, delay=1)
        if exit_code != requests.codes.ok:
            logger.error(f"Failed to download security policy from {cert[0]}, code: {exit_code}")

    @staticmethod
    def _initialize_dictionary() -> Dict[str, Any]:
        return {
            "module_name": None,
            "standard": None,
            "status": None,
            "date_sunset": None,
            "date_validation": None,
            "level": None,
            "caveat": None,
            "exceptions": None,
            "module_type": None,
            "embodiment": None,
            "tested_conf": None,
            "description": None,
            "vendor": None,
            "vendor_www": None,
            "lab": None,
            "lab_nvlap": None,
            "historical_reason": None,
            "revoked_reason": None,
            "revoked_link": None,
            "algorithms": [],
            "mentioned_certs": {},
            "tables_done": False,
            "security_policy_www": None,
            "certificate_www": None,
            "hw_versions": None,
            "fw_versions": None,
            "sw_versions": None,
            "product_url": None,
        }

    @staticmethod
    def parse_caveat(current_text: str) -> Dict[str, Dict[str, int]]:
        """
        Parses content of "Caveat" of FIPS CMVP .html file

        :param str current_text: text of "Caveat"
        :return Dict[str, Dict[str, int]]: dictionary of all found algorithm IDs
        """
        ids_found: Dict[str, Dict[str, int]] = {}
        r_key = r"(?P<word>\w+)?\s?(?:#\s?|Cert\.?(?!.\s)\s?|Certificate\s?)+(?P<id>\d+)"
        for m in re.finditer(r_key, current_text):
            if m.group("word") and m.group("word").lower() in {"rsa", "shs", "dsa", "pkcs", "aes"}:
                continue
            if m.group("id") in ids_found:
                ids_found[m.group("id")]["count"] += 1
            else:
                ids_found[m.group("id")] = {"count": 1}

        return ids_found

    @staticmethod
    def extract_algorithm_certificates(current_text: str, in_pdf: bool = False) -> List[Optional[Dict[str, List[str]]]]:
        """
        Parses table of FIPS (non) allowed algorithms

        :param str current_text: Contents of the table
        :param bool in_pdf: Specifies whether the table was found in a PDF security policies file, defaults to False
        :return List[Optional[Dict[str, List[str]]]]: List containing one element - dictionary with all parsed algorithm cert ids
        """
        set_items = set()
        if in_pdf:
            reg = r"(?:#?\s?|(?:Cert)\.?[^. ]*?\s?)(?:[CcAa]\s)?(?P<id>[CcAa]? ?\d+)"
        else:
            reg = r"(?:#[CcAa]?\s?|(?:Cert)\.?[^. ]*?\s?)(?:[CcAa]\s)?(?P<id>\d+)"
        for m in re.finditer(reg, current_text):
            set_items.add(m.group())

        return [{"Certificate": list(set_items)}] if len(set_items) > 0 else []

    @staticmethod
    def parse_table(element: Union[Tag, NavigableString]) -> List[Dict[str, Any]]:
        """
        Parses content of <table> tags in FIPS .html CMVP page

        :param Union[Tag, NavigableString] element: text in <table> tags
        :return List[Dict[str, Any]]: list of all found algorithm IDs
        """

        found_items = []
        trs = element.find_all("tr")
        for tr in trs:
            tds = tr.find_all("td")
            cert = FIPSCertificate.extract_algorithm_certificates(tds[1].text)
            if cert is None:
                continue
            found_items.append(
                {
                    "Name": tds[0].text,
                    "Certificate": cert[0]["Certificate"] if cert != [] and cert[0] is not None else [],
                    "Links": [str(x) for x in tds[1].find_all("a")],
                }
            )

        return found_items

    @staticmethod
    def _parse_html_main(current_div: Tag, html_items_found: Dict) -> None:
        pairs = {
            "Module Name": "module_name",
            "Standard": "standard",
            "Status": "status",
            "Sunset Date": "date_sunset",
            "Validation Dates": "date_validation",
            "Overall Level": "level",
            "Caveat": "caveat",
            "Security Level Exceptions": "exceptions",
            "Module Type": "module_type",
            "Embodiment": "embodiment",
            "FIPS Algorithms": "algorithms",
            "Allowed Algorithms": "algorithms",
            "Other Algorithms": "algorithms",
            "Tested Configuration(s)": "tested_conf",
            "Description": "description",
            "Historical Reason": "historical_reason",
            "Hardware Versions": "hw_versions",
            "Firmware Versions": "fw_versions",
            "Revoked Reason": "revoked_reason",
            "Revoked Link": "revoked_link",
            "Software Versions": "sw_versions",
            "Product URL": "product_url",
        }
        title = current_div.find("div", class_="col-md-3").text.strip()
        content = (
            current_div.find("div", class_="col-md-9")
            .text.strip()
            .replace("\n", "")
            .replace("\t", "")
            .replace("    ", " ")
        )

        if title in pairs:
            if "date_sunset" == pairs[title]:
                html_items_found[pairs[title]] = parser.parse(content).date()

            elif "caveat" in pairs[title]:
                html_items_found[pairs[title]] = content
                html_items_found["mentioned_certs"].update(FIPSCertificate.parse_caveat(content))

            elif "FIPS Algorithms" in title:
                html_items_found["algorithms"] += FIPSCertificate.parse_table(
                    current_div.find("div", class_="col-md-9")
                )

            elif "Algorithms" in title or "Description" in title:
                html_items_found["algorithms"] += FIPSCertificate.extract_algorithm_certificates(content)
                if "Description" in title:
                    html_items_found["description"] = content

            elif "tested_conf" in pairs[title] or "exceptions" in pairs[title]:
                html_items_found[pairs[title]] = [
                    x.text for x in current_div.find("div", class_="col-md-9").find_all("li")
                ]
            else:
                html_items_found[pairs[title]] = content

    @staticmethod
    def _parse_vendor(current_div: Tag, html_items_found: Dict, current_file: Path) -> None:
        vendor_string = current_div.find("div", "panel-body").find("a")

        if not vendor_string:
            vendor_string = list(current_div.find("div", "panel-body").children)[0].strip()
            html_items_found["vendor_www"] = ""
        else:
            html_items_found["vendor_www"] = vendor_string.get("href")
            vendor_string = vendor_string.text.strip()

        html_items_found["vendor"] = vendor_string
        if html_items_found["vendor"] == "":
            logger.warning(f"NO VENDOR FOUND {current_file}")

    @staticmethod
    def _parse_lab(current_div: Tag, html_items_found: Dict, current_file: Path) -> None:
        html_items_found["lab"] = list(current_div.find("div", "panel-body").children)[0].strip()
        html_items_found["nvlap_code"] = (
            list(current_div.find("div", "panel-body").children)[2].strip().split("\n")[1].strip()
        )

        if html_items_found["lab"] == "":
            logger.warning(f"NO LAB FOUND {current_file}")

        if html_items_found["nvlap_code"] == "":
            logger.warning(f"NO NVLAP CODE FOUND {current_file}")

    @staticmethod
    def parse_related_files(current_div: Tag, html_items_found: Dict) -> None:
        links = current_div.find_all("a")
        html_items_found["security_policy_www"] = constants.FIPS_BASE_URL + links[0].get("href")

        if len(links) == 2:
            html_items_found["certificate_www"] = constants.FIPS_BASE_URL + links[1].get("href")

    @staticmethod
    def _normalize(items: Dict) -> None:
        items["module_type"] = items["module_type"].lower().replace("-", " ").title()
        items["embodiment"] = items["embodiment"].lower().replace("-", " ").replace("stand alone", "standalone").title()

    @staticmethod
    def _parse_validation_dates(current_div: Tag, html_items_found: Dict) -> None:
        table = current_div.find("table")
        rows = table.find("tbody").findAll("tr")
        html_items_found["date_validation"] = [parser.parse(td.text).date() for td in [row.find("td") for row in rows]]

    @staticmethod
    def convert_pdf_file(tup: Tuple[FIPSCertificate, Path, Path]) -> FIPSCertificate:
        """
        Converts pdf file of FIPSCertificate. Staticmethod to allow for paralelization.

        :param Tuple[FIPSCertificate, Path, Path] tup: object which file will be converted, path to pdf, path to txt.
        :return FIPSCertificate: the modified FIPSCertificate.
        """
        cert, pdf_path, txt_path = tup
        if not cert.state.txt_state:
            exit_code = sec_certs.utils.pdf.convert_pdf_file(pdf_path, txt_path)
            if exit_code != constants.RETURNCODE_OK:
                logger.error(f"Cert dgst: {cert.cert_id} failed to convert security policy pdf->txt")
                cert.state.txt_state = False
            else:
                cert.state.txt_state = True
        return cert

    @staticmethod
    def find_keywords(cert: FIPSCertificate) -> Tuple[Optional[Dict], FIPSCertificate]:
        if not cert.state.txt_state:
            return None, cert

        keywords = sec_certs.utils.extract.extract_keywords(cert.state.sp_path.with_suffix(".pdf.txt"), fips_rules)
        return keywords, cert

    @staticmethod
    def analyze_tables(tup: Tuple[FIPSCertificate, bool]) -> Tuple[bool, FIPSCertificate, List]:
        """
        Searches for tables in pdf documents of the instance.

        :param Tuple[FIPSCertificate, bool] tup: certificate object, whether to use high precision results or approx. results
        :return Tuple[bool, FIPSCertificate, List]: True on success / False otherwise, modified cert object, List of processed tables.
        """
        cert, precision = tup
        if (not precision and cert.state.tables_done) or (
            precision and cert.heuristics.unmatched_algs < config.cert_threshold
        ):
            return cert.state.tables_done, cert, []

        cert_file = cert.state.sp_path
        txt_file = cert_file.with_suffix(".pdf.txt")
        with open(txt_file, "r", encoding="utf-8") as f:
            tables = sec_certs.utils.tables.find_tables(f.read(), txt_file)
        all_pages = precision and cert.heuristics.unmatched_algs > config.cert_threshold  # bool value

        lst: List = []
        if tables:
            try:
                data = read_pdf(cert_file, pages="all" if all_pages else tables, silent=True)
            except Exception as e:
                try:
                    logger.error(e)
                    sec_certs.utils.pdf.repair_pdf(cert_file)
                    data = read_pdf(cert_file, pages="all" if all_pages else tables, silent=True)

                except Exception as ex:
                    logger.error(ex)
                    return False, cert, lst

            # find columns with cert numbers
            for df in data:
                for col in range(len(df.columns)):
                    if "cert" in df.columns[col].lower() or "algo" in df.columns[col].lower():
                        tmp = FIPSCertificate.extract_algorithm_certificates(
                            df.iloc[:, col].to_string(index=False), True
                        )
                        lst += tmp if tmp != [{"Certificate": []}] else []
                # Parse again if someone picks not so descriptive column names
                tmp = FIPSCertificate.extract_algorithm_certificates(df.to_string(index=False))
                lst += tmp if tmp != [{"Certificate": []}] else []
        return True, cert, lst

    def _create_alg_set(self) -> Set[str]:
        result: Set[str] = set()

        if self.web_data.algorithms is None:
            raise RuntimeError(f"Algorithms were not found for cert {self.cert_id} - this should not be happening.")

        for alg in self.web_data.algorithms:
            result.update(cert for cert in alg["Certificate"])
        return result

    def _process_to_pop(self, reg_to_match: Pattern, cert: str, to_pop: Set[str]) -> None:
        for found in self.heuristics.keywords["fips_certlike"]["Certlike"]:
            match_in_found = reg_to_match.search(found)
            match_in_cert = reg_to_match.search(cert)
            if (
                match_in_found is not None
                and match_in_cert is not None
                and match_in_found.group("id") == match_in_cert.group("id")
            ):
                to_pop.add(cert)

        for alg_cert in self.heuristics.algorithms:
            for cert_no in alg_cert["Certificate"]:
                if int("".join(filter(str.isdigit, cert_no))) == int("".join(filter(str.isdigit, cert))):
                    to_pop.add(cert)

    def compute_heuristics_keywords(self) -> None:
        """
        Compute the heuristics keywords.

         - Removes algorithm mentions from the cert_id rule matches.
        """
        self.state.file_status = True
        if not self.pdf_data.keywords:
            return

        self.heuristics.keywords = copy.deepcopy(self.pdf_data.keywords)

        # XXX: Do not do this, the heuristics keywords need to be from the Security target only,
        #      because the "st_references" are computed based on these, and the "web_references"
        #      are computed based on "web_data.mentioned_certs".
        # Add the mentioned certs
        # if self.web_data.mentioned_certs:
        #     for cert_id, value in self.web_data.mentioned_certs.items():
        #         self.heuristics.keywords["fips_cert_id"]["Cert"]["#" + str(cert_id)] = value["count"]

        alg_set = self._create_alg_set()
        for cert_rule in fips_rules["fips_cert_id"]["Cert"]:
            to_pop = set()
            for cert in self.heuristics.keywords["fips_cert_id"]["Cert"]:
                if cert in alg_set:
                    to_pop.add(cert)
                    continue
                self._process_to_pop(cert_rule, cert, to_pop)

            for r in to_pop:
                self.heuristics.keywords["fips_cert_id"]["Cert"].pop(r, None)

        self.heuristics.keywords["fips_cert_id"]["Cert"].pop("#" + str(self.cert_id), None)

    @staticmethod
    def get_compare(vendor: str) -> str:
        """
        Tokenizes vendor name of the certificate.
        """
        vendor_split = (
            vendor.replace(",", "").replace("-", " ").replace("+", " ").replace("®", "").replace("(R)", "").split()
        )
        return vendor_split[0][:4] if len(vendor_split) > 0 else vendor

    def compute_heuristics_version(self) -> None:
        """
        Heuristically computes the version of the product.
        """
        versions_for_extraction = ""
        if self.web_data.module_name:
            versions_for_extraction += f" {self.web_data.module_name}"
        if self.web_data.hw_version:
            versions_for_extraction += f" {self.web_data.hw_version}"
        if self.web_data.fw_version:
            versions_for_extraction += f" {self.web_data.fw_version}"
        self.heuristics.extracted_versions = helpers.compute_heuristics_version(versions_for_extraction)
