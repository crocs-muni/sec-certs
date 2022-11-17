from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Callable, ClassVar, Dict, Final, List, Literal, Optional, Pattern, Set, Tuple

import dateutil
import numpy as np
import requests
from bs4 import BeautifulSoup, Tag
from tabula import read_pdf

import sec_certs.constants as constants
import sec_certs.utils.extract
import sec_certs.utils.helpers as helpers
import sec_certs.utils.pdf
import sec_certs.utils.tables
from sec_certs.cert_rules import FIPS_ALGS_IN_TABLE, fips_rules
from sec_certs.config.configuration import config
from sec_certs.sample.certificate import Certificate
from sec_certs.sample.certificate import Heuristics as BaseHeuristics
from sec_certs.sample.certificate import PdfData as BasePdfData
from sec_certs.sample.certificate import References, logger
from sec_certs.sample.cpe import CPE
from sec_certs.sample.fips_algorithm import FIPSAlgorithm
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.serialization.pandas import PandasSerializableType
from sec_certs.utils.helpers import fips_dgst


class FIPSHTMLParser:
    def __init__(self, soup: BeautifulSoup):
        self._soup = soup

    def build_web_data(self) -> FIPSCertificate.WebData:
        divs = self._soup.find_all("div", class_="panel panel-default")
        details_div, vendor_div, related_files_div, validation_history_div = divs

        # TODO: Move the assertions to tests
        assert len(divs) == 4
        assert details_div.find("h4").text == "Details"
        assert vendor_div.find("h4").text == "Vendor"
        assert related_files_div.find("h4").text == "Related Files"
        assert validation_history_div.find("h4").text == "Validation History"

        details_dict = self._build_details_dict(details_div)
        vendor_dict = self._build_vendor_dict(vendor_div)
        related_files_dict = self._build_related_files_dict(related_files_div)
        validation_history_dict = self._build_validation_history_dict(validation_history_div)
        return FIPSCertificate.WebData(
            **{**details_dict, **vendor_dict, **related_files_dict, **validation_history_dict}
        )

    @classmethod
    def _build_details_dict(cls, details_div: Tag) -> Dict[str, Any]:
        def parse_single_detail_entry(key, entry):
            normalized_key = DETAILS_KEY_NORMALIZATION_DICT[key]
            normalization_func = DETAILS_KEY_TO_NORMALIZATION_FUNCTION.get(normalized_key, None)
            normalized_entry = (
                FIPSHTMLParser.normalize_string(entry.text) if not normalization_func else normalization_func(entry)
            )
            return normalized_key, normalized_entry

        entries = details_div.find_all("div", class_="row padrow")
        entries = zip(
            [x.find("div", class_="col-md-3") for x in entries], [x.find("div", class_="col-md-9") for x in entries]
        )
        entries = [(FIPSHTMLParser.normalize_string(key.text), entry) for key, entry in entries]
        entries = [parse_single_detail_entry(*x) for x in entries if x[0] in DETAILS_KEY_NORMALIZATION_DICT.keys()]
        entries = dict((x, y) for x, y in entries)

        if "caveat" in entries:
            entries["mentioned_certs"] = FIPSHTMLParser.get_mentioned_certs_from_caveat(entries["caveat"])
        # TODO: Enhance algorithms with those parsed from description entry

        return entries

    @staticmethod
    def _build_vendor_dict(vendor_div: Tag) -> Dict[str, Any]:
        if not (link := vendor_div.find("a")):
            return {"vendor_url": None, "vendor": list(vendor_div.find("div", "panel-body").children)[0].strip()}
        else:
            return {"vendor_url": link.get("href"), "vendor": link.text.strip()}

    @staticmethod
    def _build_related_files_dict(related_files_div: Tag) -> Dict[str, Any]:
        if cert_link := [x for x in related_files_div.find_all("a") if "Certificate" in x.text]:
            return {"certificate_pdf_url": constants.FIPS_BASE_URL + cert_link[0].get("href")}
        else:
            return {"certificate_pdf_url": None}

    @staticmethod
    def _build_validation_history_dict(validation_history_div: Tag) -> Dict[str, Any]:
        def parse_row(row):
            validation_date, validation_type, lab = row.find_all("td")
            return FIPSCertificate.ValidationHistoryEntry(
                dateutil.parser.parse(validation_date.text).date(), validation_type.text, lab.text
            )

        rows = validation_history_div.find("tbody").find_all("tr")
        history: Optional[List[FIPSCertificate.ValidationHistoryEntry]] = [parse_row(x) for x in rows] if rows else None
        return {"validation_history": history}

    @staticmethod
    def get_mentioned_certs_from_caveat(caveat: str) -> Dict[str, int]:
        ids_found: Dict[str, int] = {}
        r_key = r"(?P<word>\w+)?\s?(?:#\s?|Cert\.?(?!.\s)\s?|Certificate\s?)+(?P<id>\d+)"
        for m in re.finditer(r_key, caveat):
            if m.group("word") and m.group("word").lower() in {"rsa", "shs", "dsa", "pkcs", "aes"}:
                continue
            if m.group("id") in ids_found:
                ids_found[m.group("id")] += 1
            else:
                ids_found[m.group("id")] = 1
        return ids_found

    @staticmethod
    def parse_algorithms(algorithms_div: Tag) -> Dict[str, Set[str]]:
        rows = algorithms_div.find("tbody").find_all("tr")
        dct: Dict[str, Set[str]] = dict()
        for row in rows:
            cells = row.find_all("td")
            dct[cells[0].text] = {m.group() for m in re.finditer(FIPS_ALGS_IN_TABLE, cells[1].text)}
        return dct

    @staticmethod
    def normalize_string(string: str) -> str:
        return " ".join(string.split())

    @staticmethod
    def parse_tested_configurations(tested_configurations: Tag) -> Optional[List[str]]:
        configurations = [y.text for y in tested_configurations.find_all("li")]
        return configurations if not configurations == ["N/A"] else None


DETAILS_KEY_NORMALIZATION_DICT: Final[Dict[str, str]] = {
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
    "Approved Algorithms": "algorithms",
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

DETAILS_KEY_TO_NORMALIZATION_FUNCTION: Dict[str, Callable] = {
    "date_sunset": lambda x: dateutil.parser.parse(x.text).date(),
    "algorithms": getattr(FIPSHTMLParser, "parse_algorithms"),
    "tested_conf": getattr(FIPSHTMLParser, "parse_tested_configurations"),
    "exceptions": lambda x: [y.text for y in x.find_all("li")],
    "status": lambda x: FIPSHTMLParser.normalize_string(x.text).lower(),
    "level": lambda x: int(FIPSHTMLParser.normalize_string(x.text)),
}


class FIPSCertificate(
    Certificate["FIPSCertificate", "FIPSCertificate.Heuristics", "FIPSCertificate.PdfData"],
    PandasSerializableType,
    ComplexSerializableType,
):
    """
    Data structure for common FIPS 140 certificate. Contains several inner classes that layer the data logic.
    Can be serialized into/from json (`ComplexSerializableType`).
    Is basic element of `FIPSDataset`. The functionality is mostly related to holding data and transformations that
    the certificate can handle itself. `FIPSDataset` class then instrument this functionality.
    """

    pandas_columns: ClassVar[List[str]] = [
        "dgst",
        "cert_id",
        "name",
        "status",
        "standard",
        "type",
        "level",
        "embodiment",
        "date_validation",
        "date_sunset",
        "algorithms",
        "extracted_versions",
        "cpe_matches",
        "verified_cpe_matches",
        "related_cves",
        "web_directly_referenced_by",
        "web_indirectly_referenced_by",
        "web_directly_referencing",
        "web_indirectly_referencing",
        "st_directly_referenced_by",
        "st_indirectly_referenced_by",
        "st_directly_referencing",
        "st_indirectly_referencing",
    ]

    @dataclass(eq=True)
    class InternalState(ComplexSerializableType):
        """
        Holds state of the `FIPSCertificate`
        """

        module_download_ok: bool
        policy_download_ok: bool

        policy_convert_garbage: bool
        policy_convert_ok: bool

        module_extract_ok: bool
        policy_extract_ok: bool

        policy_pdf_hash: Optional[str]
        policy_txt_hash: Optional[str]

        policy_pdf_path: Path
        policy_txt_path: Path
        module_html_path: Path

        errors: List[str]

        def __init__(
            self,
            module_download_ok: bool = False,
            policy_download_ok: bool = False,
            policy_convert_garbage: bool = False,
            policy_convert_ok: bool = False,
            module_extract_ok: bool = False,
            policy_extract_ok: bool = False,
            policy_pdf_hash: Optional[str] = None,
            policy_txt_hash: Optional[str] = None,
            errors: Optional[List[str]] = None,
        ):
            self.module_download_ok = module_download_ok
            self.policy_download_ok = policy_download_ok
            self.policy_convert_garbage = policy_convert_garbage
            self.policy_convert_ok = policy_convert_ok
            self.module_extract_ok = module_extract_ok
            self.policy_extract_ok = policy_extract_ok
            self.policy_pdf_hash = policy_pdf_hash
            self.policy_txt_hash = policy_txt_hash
            self.errors = errors if errors else []

        @property
        def serialized_attributes(self) -> List[str]:
            return [
                "module_download_ok",
                "policy_download_ok",
                "policy_convert_garbage",
                "policy_convert_ok",
                "module_extract_ok",
                "policy_extract_ok",
                "policy_pdf_hash",
                "policy_txt_hash",
            ]

        def module_is_ok_to_download(self, fresh: bool = True) -> bool:
            return True if fresh else not self.module_download_ok

        def policy_is_ok_to_download(self, fresh: bool = True) -> bool:
            return True if fresh else not self.policy_download_ok

        def policy_is_ok_to_convert(self, fresh: bool = True) -> bool:
            return self.policy_download_ok if fresh else self.policy_download_ok and not self.policy_convert_ok

        def module_is_ok_to_analyze(self, fresh: bool = True) -> bool:
            return self.module_download_ok if fresh else self.module_download_ok and not self.module_extract_ok

    def set_local_paths(self, policies_pdf_dir: Path, policies_txt_dir: Path, modules_html_dir: Path) -> None:
        self.state.policy_pdf_path = (policies_pdf_dir / str(self.dgst)).with_suffix(".pdf")
        self.state.policy_txt_path = (policies_txt_dir / str(self.dgst)).with_suffix(".txt")
        self.state.module_html_path = (modules_html_dir / str(self.dgst)).with_suffix(".html")

    @dataclass(eq=True)
    class ValidationHistoryEntry(ComplexSerializableType):
        date: date
        validation_type: Literal["initial", "update"]
        lab: str

        @classmethod
        def from_dict(cls, dct: Dict) -> FIPSCertificate.ValidationHistoryEntry:
            new_dct = dct.copy()
            new_dct["date"] = dateutil.parser.parse(dct["date"]).date()
            return cls(**new_dct)

    @dataclass(eq=True)
    class WebData(ComplexSerializableType):
        """
        Data structure for data obtained from scanning certificate webpage at NIST.gov
        """

        module_name: Optional[str] = field(default=None)
        validation_history: Optional[List[FIPSCertificate.ValidationHistoryEntry]] = field(default=None)
        vendor_url: Optional[str] = field(default=None)
        vendor: Optional[str] = field(default=None)
        certificate_pdf_url: Optional[str] = field(default=None)
        module_type: Optional[str] = field(default=None)
        standard: Optional[str] = field(default=None)
        status: Optional[Literal["active", "historical", "revoked"]] = field(default=None)
        level: Optional[Literal[1, 2, 3, 4]] = field(default=None)
        caveat: Optional[str] = field(default=None)
        exceptions: Optional[List[str]] = field(default=None)
        embodiment: Optional[str] = field(default=None)
        description: Optional[str] = field(default=None)
        tested_conf: Optional[List[str]] = field(default=None)
        algorithms: Optional[Dict[str, Set[str]]] = field(default=None)
        hw_versions: Optional[str] = field(default=None)
        fw_versions: Optional[str] = field(default=None)
        sw_versions: Optional[str] = field(default=None)
        mentioned_certs: Optional[Dict[str, int]] = field(default=None)  # Cert_id: n_occurences
        historical_reason: Optional[str] = field(default=None)
        date_sunset: Optional[date] = field(default=None)
        revoked_reason: Optional[str] = field(default=None)
        revoked_link: Optional[str] = field(default=None)

        # Those below are left unused at the moment
        # product_url: Optional[str] = field(default=None)

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

        @classmethod
        def from_dict(cls, dct: Dict) -> FIPSCertificate.WebData:
            new_dct = dct.copy()
            if new_dct["date_sunset"]:
                new_dct["date_sunset"] = dateutil.parser.parse(new_dct["date_sunset"]).date()
            return cls(**dct)

    @dataclass(eq=True)
    class PdfData(BasePdfData, ComplexSerializableType):
        """
        Data structure that holds data obtained from scanning pdf files (or their converted txt documents).
        """

        keywords: Dict = field(default_factory=dict)
        algorithms: Set[FIPSAlgorithm] = field(default_factory=set)
        clean_cert_ids: Dict[str, int] = field(default_factory=dict)
        st_metadata: Dict[str, Any] = field(default_factory=dict)

        # TODO: Is this meaningful? Cert id attribute got deleted.
        # def __repr__(self) -> str:
        #     return str(self.cert_id)

        # def __str__(self) -> str:
        #     return str(self.cert_id)

    @dataclass(eq=True)
    class Heuristics(BaseHeuristics, ComplexSerializableType):
        """
        Data structure that holds data obtained by processing the certificate and applying various heuristics.
        """

        # TODO: How are keywords, clean_cert_ids and algorithms attributes different from those in pdf data?
        keywords: Dict[str, Dict] = field(default_factory=dict)
        algorithms: Set[FIPSAlgorithm] = field(default_factory=set)
        unmatched_algs: Optional[int] = field(default=None)
        clean_cert_ids: Optional[Dict[str, int]] = field(default=None)

        extracted_versions: Set[str] = field(default_factory=set)
        cpe_matches: Optional[Set[str]] = field(default=None)
        verified_cpe_matches: Optional[Set[CPE]] = field(default=None)
        related_cves: Optional[Set[str]] = field(default=None)

        st_references: References = field(default_factory=References)
        web_references: References = field(default_factory=References)

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
    def module_html_url(self) -> str:
        return constants.FIPS_MODULE_URL.format(self.cert_id)

    @property
    def policy_pdf_url(self) -> str:
        return constants.FIPS_SP_URL.format(self.cert_id)

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
            + str(self.web_data.hw_versions)
            + "\n"
            + "FW version: "
            + str(self.web_data.fw_versions)
        )

    def __init__(
        self,
        cert_id: int,
        web_data: Optional[FIPSCertificate.WebData] = None,
        pdf_data: Optional[FIPSCertificate.PdfData] = None,
        heuristics: Optional[FIPSCertificate.Heuristics] = None,
        state: Optional[InternalState] = None,
    ):
        super().__init__()

        self.cert_id = cert_id
        self.web_data: FIPSCertificate.WebData = web_data if web_data else FIPSCertificate.WebData()
        self.pdf_data = pdf_data if pdf_data else FIPSCertificate.PdfData()
        self.heuristics = heuristics if heuristics else FIPSCertificate.Heuristics()
        self.state = state if state else FIPSCertificate.InternalState()

    @property
    def pandas_tuple(self) -> Tuple:
        return (
            self.dgst,
            self.cert_id,
            self.web_data.module_name,
            self.web_data.status,
            self.web_data.standard,
            self.web_data.module_type,
            self.web_data.level,
            self.web_data.embodiment,
            self.web_data.validation_history[0] if self.web_data.validation_history else np.nan,
            self.web_data.date_sunset,
            self.heuristics.algorithms,
            self.heuristics.extracted_versions,
            self.heuristics.cpe_matches,
            self.heuristics.verified_cpe_matches,
            self.heuristics.related_cves,
            self.heuristics.web_references.directly_referenced_by,
            self.heuristics.web_references.indirectly_referenced_by,
            self.heuristics.web_references.directly_referencing,
            self.heuristics.web_references.indirectly_referencing,
            self.heuristics.st_references.directly_referenced_by,
            self.heuristics.st_references.indirectly_referenced_by,
            self.heuristics.st_references.directly_referencing,
            self.heuristics.st_references.indirectly_referencing,
        )

    @staticmethod
    def parse_html_module(cert: FIPSCertificate) -> FIPSCertificate:
        with cert.state.module_html_path.open("r") as handle:
            soup = BeautifulSoup(handle, "html5lib")

        parser = FIPSHTMLParser(soup)
        cert.web_data = parser.build_web_data()

        return cert

    @staticmethod
    # TODO: This should probably get deleted
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
    def download_module(cert: FIPSCertificate) -> FIPSCertificate:
        if (exit_code := helpers.download_file(cert.module_html_url, cert.state.module_html_path)) != requests.codes.ok:
            error_msg = f"failed to download html module from {cert.module_html_url}, code {exit_code}"
            logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
            cert.state.module_download_ok = False
        else:
            cert.state.module_download_ok = True
        return cert

    @staticmethod
    def download_policy(cert: FIPSCertificate) -> FIPSCertificate:
        if (exit_code := helpers.download_file(cert.policy_pdf_url, cert.state.policy_pdf_path)) != requests.codes.ok:
            error_msg = f"failed to download pdf policy from {cert.policy_pdf_url}, code {exit_code}"
            logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
            cert.state.policy_download_ok = False
        else:
            cert.state.policy_download_ok = True
            cert.state.policy_pdf_hash = helpers.get_sha256_filepath(cert.state.policy_pdf_path)
        return cert

    @staticmethod
    def convert_policy_pdf(cert: FIPSCertificate) -> FIPSCertificate:
        ocr_done, ok_result = sec_certs.utils.pdf.convert_pdf_file(
            cert.state.policy_pdf_path, cert.state.policy_txt_path
        )

        # If OCR was done and the result was garbage
        cert.state.policy_convert_garbage = ocr_done
        # And put the whole result into convert_ok
        cert.state.policy_convert_ok = ok_result

        if not ok_result:
            error_msg = "Failed to convert policy pdf->txt"
            logger.error(f"Cert dgst: {cert.dgst}" + error_msg)
            cert.state.errors.append(error_msg)
        else:
            cert.state.policy_txt_hash = helpers.get_sha256_filepath(cert.state.policy_txt_path)

        return cert

    @staticmethod
    def extract_sp_metadata(cert: FIPSCertificate) -> FIPSCertificate:
        """Extract the PDF metadata from the security policy. Staticmethod to allow for parametrization."""
        _, metadata = sec_certs.utils.pdf.extract_pdf_metadata(cert.state.policy_pdf_path)
        cert.pdf_data.st_metadata = metadata if metadata else dict()
        return cert

    @staticmethod
    def find_keywords(cert: FIPSCertificate) -> Tuple[Optional[Dict], FIPSCertificate]:
        # TODO: Replace the condition below
        # if not cert.state.txt_state:
        #     return None, cert

        keywords = sec_certs.utils.extract.extract_keywords(
            cert.state.policy_pdf_path.with_suffix(".pdf.txt"), fips_rules
        )
        return keywords, cert

    @staticmethod
    def analyze_tables(  # noqa: C901
        tup: Tuple[FIPSCertificate, bool]
    ) -> Tuple[bool, FIPSCertificate, Set[FIPSAlgorithm]]:
        """
        Searches for tables in pdf documents of the instance.

        :param tup: certificate object, whether to use high precision results or approx. results
        :return: True on success / False otherwise, modified cert object, List of processed tables.
        """

        def extract_algorithm_certificates(current_text):
            set_items = set()
            reg = r"(?:#?\s?|(?:Cert)\.?[^. ]*?\s?)(?:[CcAa]\s)?(?P<id>[CcAa]? ?\d+)"
            for m in re.finditer(reg, current_text):
                set_items.add(m.group())
            return set(map(FIPSAlgorithm, set_items))

        cert, precision = tup
        # TODO: Not sure what this was for, fixme
        # if (not precision and cert.state.tables_done) or (
        #     precision and cert.heuristics.unmatched_algs < config.cert_threshold
        # ):
        #     return cert.state.tables_done, cert, set()

        cert_file = cert.state.policy_pdf_path
        txt_file = cert_file.with_suffix(".pdf.txt")
        with open(txt_file, "r", encoding="utf-8") as f:
            tables = sec_certs.utils.tables.find_tables(f.read(), txt_file)
        all_pages = precision and cert.heuristics.unmatched_algs > config.cert_threshold  # bool value

        lst: Set = set()
        if tables:
            try:
                data = read_pdf(cert_file, pages="all" if all_pages else tables, silent=True)
            except Exception as e:
                try:
                    logger.warn(e)
                    sec_certs.utils.pdf.repair_pdf(cert_file)
                    data = read_pdf(cert_file, pages="all" if all_pages else tables, silent=True)

                except Exception as ex:
                    logger.warn(ex)
                    return False, cert, lst

            # find columns with cert numbers
            for df in data:
                for col in range(len(df.columns)):
                    if "cert" in df.columns[col].lower() or "algo" in df.columns[col].lower():
                        tmp = extract_algorithm_certificates(df.iloc[:, col].to_string(index=False))
                        lst.update(tmp)
                # Parse again if someone picks not so descriptive column names
                tmp = extract_algorithm_certificates(df.to_string(index=False))
                lst.update(tmp)
        return True, cert, lst

    def _process_to_pop(self, reg_to_match: Pattern, cert: str, to_pop: Set[str]) -> None:
        pass

    # def _process_to_pop(self, reg_to_match: Pattern, cert: str, to_pop: Set[str]) -> None:
    #         for found in self.pdf_data.keywords["fips_certlike"]["Certlike"]:
    #             match_in_found = reg_to_match.search(found)
    #             match_in_cert = reg_to_match.search(cert)
    #             if (
    #                 match_in_found is not None
    #                 and match_in_cert is not None
    #                 and match_in_found.group("id") == match_in_cert.group("id")
    #             ):
    #                 to_pop.add(cert)

    #     this_id = int("".join(filter(str.isdigit, cert)))
    #     for algo in self.heuristics.algorithms:
    #         try:
    #             algo_id = int("".join(filter(str.isdigit, algo.cert_id)))
    #             if algo_id == this_id:
    #                 to_pop.add(cert)
    #         except ValueError:
    #             continue

    def clean_cert_ids(self) -> None:
        """
        Removes algorithm mentions from the cert_id rule matches and stores them into clean_cert_id matches.
        """
        # self.state.file_status = True # TODO: Not sure what this was for
        if not self.pdf_data.keywords:
            return

        if "Cert" not in self.pdf_data.keywords["fips_cert_id"]:
            self.pdf_data.clean_cert_ids = {}
            return

        matches = copy.deepcopy(self.pdf_data.keywords["fips_cert_id"]["Cert"])

        alg_set: Set[str] = set()
        if self.web_data.algorithms is None:
            raise RuntimeError(f"Algorithms were not found for cert {self.cert_id} - this should not be happening.")

        # TODO : Refactor this, dictionary form changed
        # for algo in self.web_data.algorithms:
        #     alg_set.add(algo.cert_id)

        for cert_rule in fips_rules["fips_cert_id"]["Cert"]:
            to_pop = set()
            for cert in matches:
                if cert in alg_set:
                    to_pop.add(cert)
                    continue
                self._process_to_pop(cert_rule, cert, to_pop)

            for r in to_pop:
                matches.pop(r, None)

        matches.pop("#" + str(self.cert_id), None)
        self.pdf_data.clean_cert_ids = matches

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
        if self.web_data.hw_versions:
            versions_for_extraction += f" {self.web_data.hw_versions}"
        if self.web_data.fw_versions:
            versions_for_extraction += f" {self.web_data.fw_versions}"
        self.heuristics.extracted_versions = helpers.compute_heuristics_version(versions_for_extraction)
