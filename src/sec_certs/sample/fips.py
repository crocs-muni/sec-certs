from __future__ import annotations

import itertools
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, ClassVar, Final, Literal

import dateutil
import numpy as np
import pandas as pd
import requests
from bs4 import BeautifulSoup, Tag

from sec_certs import constants
from sec_certs.cert_rules import FIPS_ALGS_IN_TABLE, fips_rules
from sec_certs.configuration import config
from sec_certs.sample.certificate import Certificate, References, logger
from sec_certs.sample.certificate import Heuristics as BaseHeuristics
from sec_certs.sample.certificate import PdfData as BasePdfData
from sec_certs.sample.cpe import CPE
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.serialization.pandas import PandasSerializableType
from sec_certs.utils import extract, helpers, pdf, tables
from sec_certs.utils.helpers import fips_dgst


class FIPSHTMLParser:
    def __init__(self, soup: BeautifulSoup):
        self._soup = soup

    def get_web_data_and_algorithms(self) -> tuple[set[str], FIPSCertificate.WebData]:
        divs = self._soup.find_all("div", class_="panel panel-default")
        details_div, vendor_div, related_files_div, validation_history_div = divs
        details_dict = self._build_details_dict(details_div)

        vendor_dict = self._build_vendor_dict(vendor_div)
        related_files_dict = self._build_related_files_dict(related_files_div)
        validation_history_dict = self._build_validation_history_dict(validation_history_div)

        algorithms = set()
        if "algorithms" in details_dict:
            algorithms_data = details_dict.pop("algorithms")
            for category, alg_ids in algorithms_data.items():
                algorithms |= {category + x for x in alg_ids}

        return algorithms, FIPSCertificate.WebData(
            **{**details_dict, **vendor_dict, **related_files_dict, **validation_history_dict}
        )

    def _build_details_dict(self, details_div: Tag) -> dict[str, Any]:
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
        entries = [parse_single_detail_entry(*x) for x in entries if x[0] in DETAILS_KEY_NORMALIZATION_DICT]
        entries = dict(entries)

        if "caveat" in entries:
            entries["mentioned_certs"] = FIPSHTMLParser.get_mentioned_certs_from_caveat(entries["caveat"])

        # Temporarily disabled, as this isn't extracting anything useful. Only UNKNOWN#1-9 algs were extracted over whole dataset.
        # if "description" in entries:
        #     algs = FIPSHTMLParser.get_algs_from_description(entries["description"])
        #     if "algorithms" in entries:
        #         entries["algorithms"].update({"UNKNOWN": x for x in algs})
        #     else:
        #         entries["algorithms"] = {"UNKNOWN": x for x in algs}

        return entries

    @staticmethod
    def _build_vendor_dict(vendor_div: Tag) -> dict[str, Any]:
        if not (link := vendor_div.find("a")):
            return {"vendor_url": None, "vendor": list(vendor_div.find("div", "panel-body").children)[0].strip()}
        return {"vendor_url": link.get("href"), "vendor": link.text.strip()}

    @staticmethod
    def _build_related_files_dict(related_files_div: Tag) -> dict[str, Any]:
        if cert_link := [x for x in related_files_div.find_all("a") if "Certificate" in x.text]:
            return {"certificate_pdf_url": constants.FIPS_BASE_URL + cert_link[0].get("href")}
        return {"certificate_pdf_url": None}

    @staticmethod
    def _build_validation_history_dict(validation_history_div: Tag) -> dict[str, Any]:
        def parse_row(row):
            validation_date, validation_type, lab = row.find_all("td")
            return FIPSCertificate.ValidationHistoryEntry(
                dateutil.parser.parse(validation_date.text).date(), validation_type.text, lab.text
            )

        rows = validation_history_div.find("tbody").find_all("tr")
        history: list[FIPSCertificate.ValidationHistoryEntry] | None = [parse_row(x) for x in rows] if rows else None
        return {"validation_history": history}

    @staticmethod
    def get_mentioned_certs_from_caveat(caveat: str) -> dict[str, int]:
        ids_found: dict[str, int] = {}
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
    def get_algs_from_description(description: str) -> set[str]:
        return {m.group() for m in re.finditer(FIPS_ALGS_IN_TABLE, description)}

    @staticmethod
    def parse_algorithms(algorithms_div: Tag) -> dict[str, set[str]]:
        dct: dict[str, set[str]] = {}
        table = algorithms_div.find("tbody")
        # Two types of organization on the CMVP website:
        #  - One is a table with algo references in text
        #  - Other is just divs for rows, one per algo
        if table:
            rows = table.find_all("tr")
            for row in rows:
                cells = row.find_all("td")
                dct[str(cells[0].text)] = {m.group() for m in re.finditer(FIPS_ALGS_IN_TABLE, cells[1].text)}
        else:
            rows = algorithms_div.find_all("div", class_="col-md-12")
            for row in rows:
                dct[str(row.find("div", class_="col-md-3").text)] = {
                    str(row.find("div", class_="col-md-4").text).strip()
                }
        return dct

    @staticmethod
    def normalize_type(mod_type: Tag) -> str:
        tag_text = str(mod_type.text).strip()
        return "-".join(s.capitalize() for s in tag_text.split("-"))

    @staticmethod
    def normalize_string(string: str) -> str:
        return " ".join(string.split())

    @staticmethod
    def parse_tested_configurations(tested_configurations: Tag) -> list[str] | None:
        configurations = [y.text for y in tested_configurations.find_all("li")]
        return None if configurations == ["N/A"] else configurations

    @staticmethod
    def normalize_embodiment(embodiment_element: Tag) -> str:
        text = FIPSHTMLParser.normalize_string(embodiment_element.text)
        embodiment_normalization_dict = {
            "Multi-chip embedded": "Multi-Chip Embedded",
            "Multi-chip Standalone": "Multi-Chip Stand Alone",
            "Multi-chip standalone": "Multi-Chip Stand Alone",
            "Single-chip": "Single Chip",
        }
        return embodiment_normalization_dict.get(text, text)


DETAILS_KEY_NORMALIZATION_DICT: Final[dict[str, str]] = {
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

DETAILS_KEY_TO_NORMALIZATION_FUNCTION: dict[str, Callable] = {
    "date_sunset": lambda x: dateutil.parser.parse(x.text).date(),
    "algorithms": getattr(FIPSHTMLParser, "parse_algorithms"),
    "tested_conf": getattr(FIPSHTMLParser, "parse_tested_configurations"),
    "exceptions": lambda x: [y.text for y in x.find_all("li")],
    "status": lambda x: FIPSHTMLParser.normalize_string(x.text).lower(),
    "level": lambda x: int(FIPSHTMLParser.normalize_string(x.text)),
    "embodiment": getattr(FIPSHTMLParser, "normalize_embodiment"),
    "module_type": getattr(FIPSHTMLParser, "normalize_type"),
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

    pandas_columns: ClassVar[list[str]] = [
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
        "module_directly_referenced_by",
        "module_indirectly_referenced_by",
        "module_directly_referencing",
        "module_indirectly_referencing",
        "policy_directly_referenced_by",
        "policy_indirectly_referenced_by",
        "policy_directly_referencing",
        "policy_indirectly_referencing",
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

        policy_pdf_hash: str | None
        policy_txt_hash: str | None

        _policy_pdf_path: Path | None = None
        _policy_txt_path: Path | None = None
        _module_html_path: Path | None = None

        def __init__(
            self,
            module_download_ok: bool = False,
            policy_download_ok: bool = False,
            policy_convert_garbage: bool = False,
            policy_convert_ok: bool = False,
            module_extract_ok: bool = False,
            policy_extract_ok: bool = False,
            policy_pdf_hash: str | None = None,
            policy_txt_hash: str | None = None,
        ):
            self.module_download_ok = module_download_ok
            self.policy_download_ok = policy_download_ok
            self.policy_convert_garbage = policy_convert_garbage
            self.policy_convert_ok = policy_convert_ok
            self.module_extract_ok = module_extract_ok
            self.policy_extract_ok = policy_extract_ok
            self.policy_pdf_hash = policy_pdf_hash
            self.policy_txt_hash = policy_txt_hash

        @property
        def policy_pdf_path(self) -> Path:
            if not self._policy_pdf_path:
                raise ValueError(f"policy_pdf_path not set on {type(self)}")
            return self._policy_pdf_path

        @policy_pdf_path.setter
        def policy_pdf_path(self, pth: str | Path | None) -> None:
            self._policy_pdf_path = Path(pth) if pth else None

        @property
        def policy_txt_path(self) -> Path:
            if not self._policy_txt_path:
                raise ValueError(f"policy_txt_path not set on {type(self)}")
            return self._policy_txt_path

        @policy_txt_path.setter
        def policy_txt_path(self, pth: str | Path | None) -> None:
            self._policy_txt_path = Path(pth) if pth else None

        @property
        def module_html_path(self) -> Path:
            if not self._module_html_path:
                raise ValueError(f"module_html_path not set on {type(self)}")
            return self._module_html_path

        @module_html_path.setter
        def module_html_path(self, pth: str | Path | None) -> None:
            self._module_html_path = Path(pth) if pth else None

        @property
        def serialized_attributes(self) -> list[str]:
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
            return (
                self.module_download_ok and self.module_extract_ok
                if fresh
                else self.module_download_ok and not self.module_extract_ok
            )

        def policy_is_ok_to_analyze(self, fresh: bool = True) -> bool:
            return (
                self.policy_convert_ok and self.policy_extract_ok
                if fresh
                else self.policy_convert_ok and not self.policy_extract_ok
            )

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
        def from_dict(cls, dct: dict) -> FIPSCertificate.ValidationHistoryEntry:
            new_dct = dct.copy()
            new_dct["date"] = dateutil.parser.parse(dct["date"]).date()
            return cls(**new_dct)

    @dataclass(eq=True)
    class WebData(ComplexSerializableType):
        """
        Data structure for data obtained from scanning certificate webpage at NIST.gov
        """

        module_name: str | None = field(default=None)
        validation_history: list[FIPSCertificate.ValidationHistoryEntry] | None = field(default=None)
        vendor_url: str | None = field(default=None)
        vendor: str | None = field(default=None)
        certificate_pdf_url: str | None = field(default=None)
        module_type: str | None = field(default=None)
        standard: str | None = field(default=None)
        status: Literal["active", "historical", "revoked"] | None = field(default=None)
        level: Literal[1, 2, 3, 4] | None = field(default=None)
        caveat: str | None = field(default=None)
        exceptions: list[str] | None = field(default=None)
        embodiment: str | None = field(default=None)
        description: str | None = field(default=None)
        tested_conf: list[str] | None = field(default=None)
        hw_versions: str | None = field(default=None)
        fw_versions: str | None = field(default=None)
        sw_versions: str | None = field(default=None)
        mentioned_certs: dict[str, int] | None = field(default=None)  # Cert_id: n_occurences
        historical_reason: str | None = field(default=None)
        date_sunset: date | None = field(default=None)
        revoked_reason: str | None = field(default=None)
        revoked_link: str | None = field(default=None)

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
        def from_dict(cls, dct: dict) -> FIPSCertificate.WebData:
            new_dct = dct.copy()
            if new_dct["date_sunset"]:
                new_dct["date_sunset"] = dateutil.parser.parse(new_dct["date_sunset"]).date()
            return cls(**dct)

    @dataclass(eq=True)
    class PdfData(BasePdfData, ComplexSerializableType):
        """
        Data structure that holds data obtained from scanning pdf files (or their converted txt documents).
        """

        keywords: dict = field(default_factory=dict)
        policy_metadata: dict[str, Any] = field(default_factory=dict)

        @property
        def certlike_algorithm_numbers(self) -> set[str]:
            """Returns numbers of certificates from keywords["fips_certlike"]["Certlike"]"""
            if self.keywords and "fips_certlike" in self.keywords:
                fips_certlike = self.keywords["fips_certlike"].get("Certlike", {})
                matches = {re.search(r"#\s{0,1}\d{1,4}", x) for x in fips_certlike}
                return {"".join([x for x in match.group() if x.isdigit()]) for match in matches if match}
            return set()

    @dataclass(eq=True)
    class Heuristics(BaseHeuristics, ComplexSerializableType):
        """
        Data structure that holds data obtained by processing the certificate and applying various heuristics.
        """

        algorithms: set[str] = field(default_factory=set)
        extracted_versions: set[str] = field(default_factory=set)
        cpe_matches: set[str] | None = field(default=None)
        verified_cpe_matches: set[CPE] | None = field(default=None)
        related_cves: set[str] | None = field(default=None)
        policy_prunned_references: set[str] = field(default_factory=set)
        module_prunned_references: set[str] = field(default_factory=set)
        policy_processed_references: References = field(default_factory=References)
        module_processed_references: References = field(default_factory=References)
        direct_transitive_cves: set[str] | None = field(default=None)
        indirect_transitive_cves: set[str] | None = field(default=None)

        @property
        def algorithm_numbers(self) -> set[str]:
            """Returns numbers of algorithms"""

            def alg_to_number(alg: str) -> str:
                return "".join([x for x in alg.split("#")[1] if x.isdigit()])

            return {alg_to_number(x) for x in self.algorithms}

    @property
    def dgst(self) -> str:
        """
        Returns primary key of the certificate, its id.
        """
        return fips_dgst(self.cert_id)

    @property
    def manufacturer(self) -> str | None:  # type: ignore
        return self.web_data.vendor

    @property
    def module_html_url(self) -> str:
        return constants.FIPS_MODULE_URL.format(self.cert_id)

    @property
    def policy_pdf_url(self) -> str:
        return constants.FIPS_SP_URL.format(self.cert_id)

    @property
    def name(self) -> str | None:  # type: ignore
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
        web_data: FIPSCertificate.WebData | None = None,
        pdf_data: FIPSCertificate.PdfData | None = None,
        heuristics: FIPSCertificate.Heuristics | None = None,
        state: InternalState | None = None,
    ):
        super().__init__()

        self.cert_id = cert_id
        self.web_data: FIPSCertificate.WebData = web_data if web_data else FIPSCertificate.WebData()
        self.pdf_data: FIPSCertificate.PdfData = pdf_data if pdf_data else FIPSCertificate.PdfData()
        self.heuristics: FIPSCertificate.Heuristics = heuristics if heuristics else FIPSCertificate.Heuristics()
        self.state: FIPSCertificate.InternalState = state if state else FIPSCertificate.InternalState()

    @property
    def pandas_tuple(self) -> tuple:
        return (
            self.dgst,
            self.cert_id,
            self.web_data.module_name,
            self.web_data.status,
            self.web_data.standard,
            self.web_data.module_type,
            self.web_data.level,
            self.web_data.embodiment,
            self.web_data.validation_history[0].date if self.web_data.validation_history else np.nan,
            self.web_data.date_sunset,
            self.heuristics.algorithms,
            self.heuristics.extracted_versions,
            self.heuristics.cpe_matches,
            self.heuristics.verified_cpe_matches,
            self.heuristics.related_cves,
            self.heuristics.module_processed_references.directly_referenced_by,
            self.heuristics.module_processed_references.indirectly_referenced_by,
            self.heuristics.module_processed_references.directly_referencing,
            self.heuristics.module_processed_references.indirectly_referencing,
            self.heuristics.policy_processed_references.directly_referenced_by,
            self.heuristics.policy_processed_references.indirectly_referenced_by,
            self.heuristics.policy_processed_references.directly_referencing,
            self.heuristics.policy_processed_references.indirectly_referencing,
        )

    @staticmethod
    def parse_html_module(cert: FIPSCertificate) -> FIPSCertificate:
        with cert.state.module_html_path.open("r") as handle:
            soup = BeautifulSoup(handle, "html5lib")

        parser = FIPSHTMLParser(soup)
        algorithms, cert.web_data = parser.get_web_data_and_algorithms()
        cert.heuristics.algorithms |= algorithms
        cert.state.module_extract_ok = True

        return cert

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
        """
        Converts policy pdf -> txt
        """
        ocr_done, ok_result = pdf.convert_pdf_file(cert.state.policy_pdf_path, cert.state.policy_txt_path)

        # If OCR was done and the result was garbage
        cert.state.policy_convert_garbage = ocr_done
        # And put the whole result into convert_ok
        cert.state.policy_convert_ok = ok_result

        if not ok_result:
            error_msg = "Failed to convert policy pdf->txt"
            logger.error(f"Cert dgst: {cert.dgst}" + error_msg)
        else:
            cert.state.policy_txt_hash = helpers.get_sha256_filepath(cert.state.policy_txt_path)

        return cert

    @staticmethod
    def extract_policy_pdf_metadata(cert: FIPSCertificate) -> FIPSCertificate:
        """
        Extract the PDF metadata from the security policy.
        """
        _, metadata = pdf.extract_pdf_metadata(cert.state.policy_pdf_path)

        if metadata:
            cert.pdf_data.policy_metadata = metadata
        else:
            cert.pdf_data.policy_metadata = {}
            cert.state.policy_extract_ok = False
        return cert

    @staticmethod
    def extract_policy_pdf_keywords(cert: FIPSCertificate) -> FIPSCertificate:
        """
        Extract keywords from policy document
        """
        keywords = extract.extract_keywords(cert.state.policy_txt_path, fips_rules)
        if not keywords:
            cert.state.policy_extract_ok = False
        else:
            cert.pdf_data.keywords = keywords
        return cert

    @staticmethod
    def get_algorithms_from_policy_tables(cert: FIPSCertificate):
        """
        Retrieves IDs of algorithms from tables inside security policy pdfs.
        External library is used to handle this.
        """
        from tabula import read_pdf

        if table_rich_page_numbers := tables.find_pages_with_tables(cert.state.policy_txt_path):
            pdf.repair_pdf(cert.state.policy_pdf_path)
            try:
                tabular_data = read_pdf(cert.state.policy_pdf_path, pages=list(table_rich_page_numbers), silent=True)
                cert.heuristics.algorithms |= set(
                    itertools.chain.from_iterable(
                        tables.get_algs_from_table(df.to_string())
                        for df in tabular_data
                        if isinstance(df, pd.DataFrame)
                    )
                )
            except Exception as e:
                logger.warning(f"Error when parsing tables from {cert.dgst}: {e}")
                cert.state.policy_extract_ok = False

    def prune_referenced_cert_ids(self) -> None:
        """
        This method goes through all IDs (numbers) that correspond to FIPS Certificates and are stored in
        pdf_data.keywords or web_data.mentioned_certs. It performs prunning of these attributes and fills attributes
        heuristics.prunned_module_references and heuristics.prunned_policy_references. These variables are further
        processed and Reference objects are created from them.
        """
        html_module_ids = set(self.web_data.mentioned_certs.keys()) if self.web_data.mentioned_certs else set()
        self.heuristics.module_prunned_references = self._prune_reference_ids_variable(html_module_ids)

        if self.pdf_data.keywords:
            pdf_policy_ids = set(self.pdf_data.keywords["fips_cert_id"].get("Cert", {}).keys())
            pdf_policy_ids = {"".join([y for y in x if y.isdigit()]) for x in pdf_policy_ids}
        else:
            pdf_policy_ids = set()

        self.heuristics.policy_prunned_references = self._prune_reference_ids_variable(pdf_policy_ids)

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

    def _prune_reference_ids_variable(self, attribute_to_prune: set[str]) -> set[str]:
        """
        Prunnes cert_ids from variable "attribute_to_prune", return result. Steps:
            0. Consider only ids != self.cert_id
            1. Consider only ids > config.always_false_positive_fips_cert_id_threshold
            2. Consider only ids s.t. they don't appear in self.heuristics.algorithms
            3. Consider only ids s.t. they don't appear in self.pdf_data.keywords["fips_certlike"]["Certlike"]
        """
        prunned = {x for x in attribute_to_prune if x != str(self.cert_id)}
        prunned = {x for x in prunned if int(x) > config.always_false_positive_fips_cert_id_threshold}
        prunned = {x for x in prunned if x not in self.heuristics.algorithm_numbers}
        return {x for x in prunned if x not in self.pdf_data.certlike_algorithm_numbers}
