# mypy: ignore-errors
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Literal, Union
from urllib.parse import unquote_plus, urlparse

import numpy as np
import requests

from sec_certs.cert_rules import SARS_IMPLIED_FROM_EAL, cc_rules
from sec_certs.configuration import config
from sec_certs.converter import PDFConverter
from sec_certs.sample.certificate import logger
from sec_certs.sample.sar import SAR
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.serialization.pandas import PandasSerializableType
from sec_certs.utils import helpers, sanitization
from sec_certs.utils.extract import extract_keywords, scheme_frontpage_functions
from sec_certs.utils.pdf import extract_pdf_metadata

if TYPE_CHECKING:
    from sec_certs.sample.cc import CCCertificate
    from sec_certs.sample.eucc import EUCCCertificate


class CC_EUCC_SampleMixin(PandasSerializableType, ComplexSerializableType):
    CC_EUCC_Certificate = Union["CCCertificate", "EUCCCertificate"]

    pandas_columns: ClassVar[list[str]] = [
        "dgst",
        "cert_id",
        "name",
        "status",
        "category",
        "manufacturer",
        "scheme",
        "security_level",
        "eal",
        "not_valid_before",
        "not_valid_after",
        "report_link",
        "st_link",
        "cert_link",
        "manufacturer_web",
        "extracted_versions",
        "cpe_matches",
        "verified_cpe_matches",
        "related_cves",
        "directly_referenced_by",
        "indirectly_referenced_by",
        "directly_referencing",
        "indirectly_referencing",
        "extracted_sars",
        "protection_profile_links",
        "protection_profiles",
        "cert_lab",
    ]

    @property
    def dgst(self) -> str:
        """
        Computes the primary key of the sample using first 16 bytes of SHA-256 digest
        """
        if not (self.name is not None and self.category is not None):
            raise RuntimeError("Certificate digest can't be computed, because information is missing.")
        return helpers.get_first_16_bytes_sha256(
            "|".join(
                [
                    self.category,
                    self.name,
                    sanitization.sanitize_link_fname(self.report_link) or "None",
                    sanitization.sanitize_link_fname(self.st_link) or "None",
                ]
            )
        )

    @property
    def actual_sars(self) -> set[SAR] | None:
        """
        Computes actual SARs. First, SARs implied by EAL are computed. Then, these are augmented with heuristically extracted SARs.

        :return Optional[Set[SAR]]: Set of actual SARs of a certificate, None if empty
        """
        sars = {}
        if self.heuristics.eal:
            sars = {x[0]: SAR(x[0], x[1]) for x in SARS_IMPLIED_FROM_EAL[self.heuristics.eal[:4]]}

        if self.heuristics.extracted_sars:
            for sar in self.heuristics.extracted_sars:
                if sar not in sars or sar.level > sars[sar.family].level:
                    sars[sar.family] = sar

        return set(sars.values()) if sars else None

    @property
    def label_studio_title(self) -> str | None:
        return self.name

    @property
    def pandas_tuple(self) -> tuple:
        """
        Returns tuple of attributes meant for pandas serialization
        """
        return (
            self.dgst,
            self.heuristics.cert_id,
            self.name,
            self.status,
            self.category,
            self.manufacturer,
            self.scheme,
            self.security_level,
            self.heuristics.eal,
            self.not_valid_before,
            self.not_valid_after,
            self.report_link,
            self.st_link,
            self.cert_link,
            self.manufacturer_web,
            self.heuristics.extracted_versions,
            self.heuristics.cpe_matches,
            self.heuristics.verified_cpe_matches,
            self.heuristics.related_cves,
            self.heuristics.report_references.directly_referenced_by,
            self.heuristics.report_references.indirectly_referenced_by,
            self.heuristics.report_references.directly_referencing,
            self.heuristics.report_references.indirectly_referencing,
            self.heuristics.extracted_sars,
            self.protection_profile_links if self.protection_profile_links else np.nan,
            self.heuristics.protection_profiles if self.heuristics.protection_profiles else np.nan,
            self.heuristics.cert_lab[0] if (self.heuristics.cert_lab and self.heuristics.cert_lab[0]) else np.nan,
        )

    def __str__(self) -> str:
        printed_manufacturer = self.manufacturer if self.manufacturer else "Unknown manufacturer"
        return str(printed_manufacturer) + " " + str(self.name) + " dgst: " + self.dgst

    def set_local_paths(
        self,
        report_pdf_dir: str | Path | None,
        st_pdf_dir: str | Path | None,
        cert_pdf_dir: str | Path | None,
        report_txt_dir: str | Path | None,
        st_txt_dir: str | Path | None,
        cert_txt_dir: str | Path | None,
        report_json_dir: str | Path | None,
        st_json_dir: str | Path | None,
        cert_json_dir: str | Path | None,
    ) -> None:
        """
        Sets paths to files given the requested directories

        :param Optional[Union[str, Path]] report_pdf_dir: Directory where pdf reports shall be stored
        :param Optional[Union[str, Path]] st_pdf_dir: Directory where pdf security targets shall be stored
        :param Optional[Union[str, Path]] cert_pdf_dir: Directory where pdf certificates shall be stored
        :param Optional[Union[str, Path]] report_txt_dir: Directory where txt reports shall be stored
        :param Optional[Union[str, Path]] st_txt_dir: Directory where txt security targets shall be stored
        :param Optional[Union[str, Path]] cert_txt_dir: Directory where txt certificates shall be stored
        :param Optional[Union[str, Path]] report_json_dir: Directory where json reports shall be stored
        :param Optional[Union[str, Path]] st_json_dir: Directory where json security targets shall be stored
        :param Optional[Union[str, Path]] cert_json_dir: Directory where json certificates shall be stored
        """
        if report_pdf_dir:
            self.state.report.pdf_path = Path(report_pdf_dir) / (self.dgst + ".pdf")
        if st_pdf_dir:
            self.state.st.pdf_path = Path(st_pdf_dir) / (self.dgst + ".pdf")
        if cert_pdf_dir:
            self.state.cert.pdf_path = Path(cert_pdf_dir) / (self.dgst + ".pdf")

        if report_txt_dir:
            self.state.report.txt_path = Path(report_txt_dir) / (self.dgst + ".txt")
        if st_txt_dir:
            self.state.st.txt_path = Path(st_txt_dir) / (self.dgst + ".txt")
        if cert_txt_dir:
            self.state.cert.txt_path = Path(cert_txt_dir) / (self.dgst + ".txt")

        if report_json_dir:
            self.state.report.json_path = Path(report_json_dir) / (self.dgst + ".json")
        if st_json_dir:
            self.state.st.json_path = Path(st_json_dir) / (self.dgst + ".json")
        if cert_json_dir:
            self.state.cert.json_path = Path(cert_json_dir) / (self.dgst + ".json")

    def compute_heuristics_version(self) -> None:
        """
        Fills in the heuristically obtained version of certified product into attribute in heuristics class.
        """
        self.heuristics.extracted_versions = helpers.compute_heuristics_version(self.name) if self.name else set()

    @staticmethod
    def _extract_pdf_metadata_(
        cert: CC_EUCC_Certificate, doc_type: Literal["report", "st", "cert"]
    ) -> CC_EUCC_Certificate:
        doc_state = getattr(cert.state, doc_type)
        try:
            metadata = extract_pdf_metadata(doc_state.pdf_path)
            setattr(cert.pdf_data, f"{doc_type}_metadata", metadata)
            doc_state.extract_ok = True
        except ValueError:
            doc_state.extract_ok = False
        return cert

    @staticmethod
    def _extract_pdf_keywords(
        cert: CC_EUCC_Certificate, doc_type: Literal["report", "st", "cert"]
    ) -> CC_EUCC_Certificate:
        doc_state = getattr(cert.state, doc_type)
        try:
            keywords = extract_keywords(doc_state.txt_path, cc_rules)
            if keywords is None:
                doc_state.extract_ok = False
            else:
                setattr(cert.pdf_data, f"{doc_type}_keywords", keywords)
        except ValueError:
            doc_state.extract_ok = False
        return cert

    @staticmethod
    def extract_report_pdf_metadata(cert: CC_EUCC_Certificate) -> CC_EUCC_Certificate:
        """
        Extracts metadata from certification report pdf given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to extract the metadata for.
        :return CCCertificate: the modified certificate with updated state
        """
        return CC_EUCC_SampleMixin._extract_pdf_metadata_(cert, "report")

    @staticmethod
    def extract_st_pdf_metadata(cert: CC_EUCC_Certificate) -> CC_EUCC_Certificate:
        """
        Extracts metadata from security target pdf given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to extract the metadata for.
        :return CCCertificate: the modified certificate with updated state
        """
        return CC_EUCC_SampleMixin._extract_pdf_metadata_(cert, "st")

    @staticmethod
    def extract_cert_pdf_metadata(cert: CC_EUCC_Certificate) -> CC_EUCC_Certificate:
        """
        Extracts metadata from certificate pdf given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to extract the metadata for.
        :return CCCertificate: the modified certificate with updated state
        """
        return CC_EUCC_SampleMixin._extract_pdf_metadata_(cert, "cert")

    @staticmethod
    def extract_report_pdf_keywords(cert: CC_EUCC_Certificate) -> CC_EUCC_Certificate:
        """
        Matches regular expressions in txt obtained from certification report and extracts the matches into attribute.
        Static method to allow for parallelization

        :param CCCertificate cert: certificate to extract the keywords for.
        :return CCCertificate: the modified certificate with extracted keywords.
        """
        return CC_EUCC_SampleMixin._extract_pdf_keywords(cert, "report")

    @staticmethod
    def extract_st_pdf_keywords(cert: CC_EUCC_Certificate) -> CC_EUCC_Certificate:
        """
        Matches regular expressions in txt obtained from security target and extracts the matches into attribute.
        Static method to allow for parallelization

        :param CCCertificate cert: certificate to extract the keywords for.
        :return CCCertificate: the modified certificate with extracted keywords.
        """
        return CC_EUCC_SampleMixin._extract_pdf_keywords(cert, "st")

    @staticmethod
    def extract_cert_pdf_keywords(cert: CC_EUCC_Certificate) -> CC_EUCC_Certificate:
        """
        Matches regular expressions in txt obtained from the certificate and extracts the matches into attribute.
        Static method to allow for parallelization

        :param CCCertificate cert: certificate to extract the keywords for.
        :return CCCertificate: the modified certificate with extracted keywords.
        """
        return CC_EUCC_SampleMixin._extract_pdf_keywords(cert, "cert")

    @staticmethod
    def extract_report_pdf_frontpage(cert: CC_EUCC_Certificate) -> CC_EUCC_Certificate:
        """
        Extracts data from certification report pdf frontpage given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to extract the frontpage data for.
        :return CCCertificate: the modified certificate with updated state
        """
        cert.pdf_data.report_frontpage = {}

        if cert.scheme in scheme_frontpage_functions:
            header_func = scheme_frontpage_functions[cert.scheme]
            try:
                cert.pdf_data.report_frontpage[cert.scheme] = header_func(cert.state.report.txt_path)
            except ValueError:
                cert.state.report.extract_ok = False
        return cert

    @staticmethod
    def _convert_pdf(
        cert: CC_EUCC_Certificate, doc_type: Literal["report", "st", "cert"], converter: PDFConverter
    ) -> CCCertificate:
        doc_state = getattr(cert.state, doc_type)
        ok_result = converter.convert(doc_state.pdf_path, doc_state.txt_path, doc_state.json_path)
        doc_state.convert_ok = ok_result
        if not ok_result:
            error_msg = f"failed to convert {doc_type} pdf->txt"
            logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
        else:
            doc_state.txt_hash = helpers.get_sha256_filepath(doc_state.txt_path)
            if doc_state.json_path.exists():
                doc_state.json_hash = helpers.get_sha256_filepath(doc_state.json_path)
            else:
                doc_state.json_hash = None
        return cert

    @staticmethod
    def _download_pdf(cert: CC_EUCC_Certificate, doc_type: Literal["report", "st", "cert"]):
        link = getattr(cert, f"{doc_type}_link")
        doc_state = getattr(cert.state, doc_type)
        exit_code = helpers.download_file(link, doc_state.pdf_path, proxy=config.cc_use_proxy) if link else "No link"

        if exit_code != requests.codes.ok:
            error_msg = f"failed to download {doc_type} from {link}, code: {exit_code}"
            logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
            doc_state.download_ok = False
        else:
            doc_state.download_ok = True
            doc_state.pdf_hash = helpers.get_sha256_filepath(doc_state.pdf_path)
            setattr(cert.pdf_data, f"{doc_type}_filename", unquote_plus(str(urlparse(link).path).split("/")[-1]))
        return cert

    @staticmethod
    def download_pdf_report(cert: CC_EUCC_Certificate) -> CC_EUCC_Certificate:
        """
        Downloads pdf of certification report given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to download the pdf report for
        :return CCCertificate: returns the modified certificate with updated state
        """
        return CC_EUCC_SampleMixin._download_pdf(cert, "report")

    @staticmethod
    def download_pdf_st(cert: CC_EUCC_Certificate) -> CC_EUCC_Certificate:
        """
        Downloads pdf of security target given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to download the pdf security target for
        :return CCCertificate: returns the modified certificate with updated state
        """
        return CC_EUCC_SampleMixin._download_pdf(cert, "st")

    @staticmethod
    def download_pdf_cert(cert: CC_EUCC_Certificate) -> CC_EUCC_Certificate:
        """
        Downloads pdf of the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to download the pdf of
        :return CCCertificate: returns the modified certificate with updated state
        """
        return CC_EUCC_SampleMixin._download_pdf(cert, "cert")

    @staticmethod
    def convert_report_pdf(cert: CC_EUCC_Certificate, converter: PDFConverter) -> CC_EUCC_Certificate:
        """
        Converts the pdf certification report to txt, given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to convert the pdf report for
        :return CCCertificate: the modified certificate with updated state
        """
        return CC_EUCC_SampleMixin._convert_pdf(cert, "report", converter)

    @staticmethod
    def convert_st_pdf(cert: CC_EUCC_Certificate, converter: PDFConverter) -> CC_EUCC_Certificate:
        """
        Converts the pdf security target to txt, given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to convert the pdf security target for
        :return CCCertificate: the modified certificate with updated state
        """
        return CC_EUCC_SampleMixin._convert_pdf(cert, "st", converter)

    @staticmethod
    def convert_cert_pdf(cert: CC_EUCC_Certificate, converter: PDFConverter) -> CC_EUCC_Certificate:
        """
        Converts the pdf certificate to txt, given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to convert the certificate for
        :return CCCertificate: the modified certificate with updated state
        """
        return CC_EUCC_SampleMixin._convert_pdf(cert, "cert", converter)

    def compute_heuristics_cert_lab(self) -> None:
        """
        Fills in the heuristically obtained evaluation laboratory into attribute in heuristics class.
        """
        if not self.pdf_data:
            logger.error("Cannot compute sample lab when pdf files were not processed.")
            return
        self.heuristics.cert_lab = self.pdf_data.cert_lab

    def compute_heuristics_cert_id(self):
        """
        Compute the heuristics cert_id of this cert, using several methods.

        The candidate cert_ids are extracted from the frontpage, PDF metadata, filename, and keywords matches.

        Finally, the cert_id is canonicalized.
        """
        if not self.pdf_data:
            logger.warning("Cannot compute sample id when pdf files were not processed.")
            return
        # Extract candidate cert_ids
        candidates = self.pdf_data.candidate_cert_ids(self.scheme)

        if candidates:
            max_weight = max(candidates.values())
            max_candidates = list(filter(lambda x: candidates[x] == max_weight, candidates.keys()))
            max_candidates.sort(key=len, reverse=True)
            self.heuristics.cert_id = max_candidates[0]
