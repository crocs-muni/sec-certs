from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Literal

import dateutil
import numpy as np
import pandas as pd
import requests
from bs4 import BeautifulSoup

from sec_certs import constants
from sec_certs.cert_rules import fips_rules
from sec_certs.configuration import config
from sec_certs.sample.certificate import Certificate, References, logger
from sec_certs.sample.certificate import Heuristics as BaseHeuristics
from sec_certs.sample.certificate import PdfData as BasePdfData
from sec_certs.sample.cpe import CPE
from sec_certs.sample.document_state import DocumentState
from sec_certs.sample.fips_html_parser import FIPSHTMLParser
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.serialization.pandas import PandasSerializableType
from sec_certs.utils import extract, helpers, tables
from sec_certs.utils.helpers import fips_dgst
from sec_certs.utils.pdf import extract_pdf_metadata, repair_pdf

if TYPE_CHECKING:
    from sec_certs.converter import PDFConverter


@dataclass
class InternalState(ComplexSerializableType):
    module: DocumentState = field(default_factory=DocumentState)
    policy: DocumentState = field(default_factory=DocumentState)


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

            return {alg_to_number(x) for x in self.algorithms if "#" in x}

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
        self.state: InternalState = state if state else InternalState()

    def set_local_paths(
        self, policies_pdf_dir: Path, policies_txt_dir: Path, policies_json_dir: Path, modules_html_dir: Path
    ) -> None:
        self.state.policy.source_path = (policies_pdf_dir / str(self.dgst)).with_suffix(".pdf")
        self.state.policy.txt_path = (policies_txt_dir / str(self.dgst)).with_suffix(".txt")
        self.state.policy.json_path = (policies_json_dir / str(self.dgst)).with_suffix(".json")
        self.state.module.source_path = (modules_html_dir / str(self.dgst)).with_suffix(".html")

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
        with cert.state.module.source_path.open("r") as handle:
            soup = BeautifulSoup(handle, "html5lib")

        parser = FIPSHTMLParser(soup)
        algorithms, cert.web_data = parser.get_web_data_and_algorithms()
        cert.heuristics.algorithms |= algorithms
        cert.state.module.extract_ok = True

        return cert

    @staticmethod
    def download_module(cert: FIPSCertificate) -> FIPSCertificate:
        if (
            exit_code := helpers.download_file(
                cert.module_html_url, cert.state.module.source_path, proxy=config.fips_use_proxy
            )
        ) != requests.codes.ok:
            error_msg = f"failed to download html module from {cert.module_html_url}, code {exit_code}"
            logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
            cert.state.module.download_ok = False
        else:
            cert.state.module.download_ok = True
            cert.state.module.convert_ok = True  # No conversion needed for html, so we set it to True

        return cert

    @staticmethod
    def download_policy(cert: FIPSCertificate) -> FIPSCertificate:
        if (
            exit_code := helpers.download_file(
                cert.policy_pdf_url, cert.state.policy.source_path, proxy=config.fips_use_proxy
            )
        ) != requests.codes.ok:
            error_msg = f"failed to download pdf policy from {cert.policy_pdf_url}, code {exit_code}"
            logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
            cert.state.policy.download_ok = False
        else:
            cert.state.policy.download_ok = True
            cert.state.policy.source_hash = helpers.get_sha256_filepath(cert.state.policy.source_path)
        return cert

    @staticmethod
    def convert_policy_pdf(cert: FIPSCertificate, converter: PDFConverter) -> FIPSCertificate:
        """
        Converts policy pdf -> txt, json
        """
        ok_result = converter.convert(
            cert.state.policy.source_path, cert.state.policy.txt_path, cert.state.policy.json_path
        )
        cert.state.policy.convert_ok = ok_result
        if not ok_result:
            error_msg = "Failed to convert policy pdf->txt"
            logger.error(f"Cert dgst: {cert.dgst}" + error_msg)
        else:
            cert.state.policy.txt_hash = helpers.get_sha256_filepath(cert.state.policy.txt_path)
            if cert.state.policy.json_path.exists():
                cert.state.policy.json_hash = helpers.get_sha256_filepath(cert.state.policy.json_path)
            else:
                cert.state.policy.json_hash = None
        return cert

    @staticmethod
    def extract_policy_pdf_metadata(cert: FIPSCertificate) -> FIPSCertificate:
        """
        Extract the PDF metadata from the security policy.
        """
        try:
            cert.pdf_data.policy_metadata = extract_pdf_metadata(cert.state.policy.source_path)
            cert.state.policy.extract_ok = True
        except ValueError:
            cert.state.policy.extract_ok = False
        return cert

    @staticmethod
    def extract_policy_pdf_keywords(cert: FIPSCertificate) -> FIPSCertificate:
        """
        Extract keywords from policy document
        """
        keywords = extract.extract_keywords(cert.state.policy.txt_path, fips_rules)
        if not keywords:
            cert.state.policy.extract_ok = False
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

        if table_rich_page_numbers := tables.find_pages_with_tables(cert.state.policy.txt_path):
            repair_pdf(cert.state.policy.source_path)
            try:
                tabular_data = read_pdf(cert.state.policy.source_path, pages=list(table_rich_page_numbers), silent=True)
                cert.heuristics.algorithms |= set(
                    itertools.chain.from_iterable(
                        tables.get_algs_from_table(df.to_string())
                        for df in tabular_data
                        if isinstance(df, pd.DataFrame)
                    )
                )
            except Exception as e:
                logger.warning(f"Error when parsing tables from {cert.dgst}: {e}")
                cert.state.policy.extract_ok = False

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
