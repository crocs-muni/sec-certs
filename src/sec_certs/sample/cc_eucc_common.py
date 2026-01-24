"""
This module contains logic shared exclusively between `CCCertificate` and `EUCCCertificate`.

It is intentionally scoped to these two datasets only, as they share a substantial
portion of processing and heuristics logic that does not apply to other dataset
types in the codebase.

Includes:
    - InternalState class
    - Heuristics class
    - PdfData class
    - Functions for downloading, converting, and extracting data from PDFs
    - Utility functions for computing digests and heuristics
"""

from __future__ import annotations

import copy
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote_plus, urlparse

import requests

from sec_certs.cert_rules import SARS_IMPLIED_FROM_EAL, cc_rules, rules
from sec_certs.configuration import config
from sec_certs.sample.cc_certificate_id import canonicalize, schemes
from sec_certs.sample.certificate import Heuristics as BaseHeuristics
from sec_certs.sample.certificate import PdfData as BasePdfData
from sec_certs.sample.certificate import References, logger
from sec_certs.sample.document_state import DocumentState
from sec_certs.sample.sar import SAR
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils import helpers, sanitization
from sec_certs.utils.extract import extract_keywords, normalize_match_string, scheme_frontpage_functions
from sec_certs.utils.helpers import DocType
from sec_certs.utils.pdf import extract_pdf_metadata

if TYPE_CHECKING:
    from sec_certs.converter import PDFConverter
    from sec_certs.sample.cc import CCCertificate
    from sec_certs.sample.eucc import EUCCCertificate


@dataclass
class InternalState(ComplexSerializableType):
    """
    Holds internal state of the certificate, whether downloads and converts of individual components succeeded. Also
    holds information about errors and paths to the files.
    """

    report: DocumentState = field(default_factory=DocumentState)
    st: DocumentState = field(default_factory=DocumentState)
    cert: DocumentState = field(default_factory=DocumentState)


@dataclass
class Heuristics(BaseHeuristics, ComplexSerializableType):
    """
    Class for various heuristics related to CCCertificate and EUCCCertificate.
    """

    extracted_versions: set[str] | None = field(default=None)
    cpe_matches: set[str] | None = field(default=None)
    verified_cpe_matches: set[str] | None = field(default=None)
    related_cves: set[str] | None = field(default=None)
    cert_lab: list[str] | None = field(default=None)
    cert_id: str | None = field(default=None)
    prev_certificates: list[str] | None = field(default=None)
    next_certificates: list[str] | None = field(default=None)
    st_references: References = field(default_factory=References)
    report_references: References = field(default_factory=References)
    # Contains direct outward references merged from both st, and report sources, annotated with ReferenceAnnotator
    # TODO: Reference meanings as Enum if we work with it further.
    annotated_references: dict[str, str] | None = field(default=None)
    extracted_sars: set[SAR] | None = field(default=None)
    direct_transitive_cves: set[str] | None = field(default=None)
    indirect_transitive_cves: set[str] | None = field(default=None)
    scheme_data: dict[str, Any] | None = field(default=None)
    protection_profiles: set[str] | None = field(default=None)
    eal: str | None = field(default=None)

    @property
    def serialized_attributes(self) -> list[str]:
        return copy.deepcopy(super().serialized_attributes)


@dataclass
class PdfData(BasePdfData, ComplexSerializableType):
    """
    Class that holds data extracted from pdf files.
    """

    report_metadata: dict[str, Any] | None = field(default=None)
    st_metadata: dict[str, Any] | None = field(default=None)
    cert_metadata: dict[str, Any] | None = field(default=None)
    report_frontpage: dict[str, dict[str, Any]] | None = field(default=None)
    st_frontpage: dict[str, dict[str, Any]] | None = field(
        default=None
    )  # TODO: Unused, we have no frontpage matching for targets
    cert_frontpage: dict[str, dict[str, Any]] | None = field(
        default=None
    )  # TODO: Unused, we have no frontpage matching for certs
    report_keywords: dict[str, Any] | None = field(default=None)
    st_keywords: dict[str, Any] | None = field(default=None)
    cert_keywords: dict[str, Any] | None = field(default=None)
    report_filename: str | None = field(default=None)
    st_filename: str | None = field(default=None)
    cert_filename: str | None = field(default=None)

    def __bool__(self) -> bool:
        return any(x is not None for x in vars(self))

    @property
    def cert_lab(self) -> list[str] | None:
        """
        Returns labs for which certificate data was parsed.
        """
        if not self.report_frontpage:
            return None
        labs = [
            data["cert_lab"].split(" ")[0].upper()
            for scheme, data in self.report_frontpage.items()
            if data and "cert_lab" in data
        ]
        return labs if labs else None

    def frontpage_cert_id(self, scheme: str) -> dict[str, float]:
        """
        Get cert_id candidate from the frontpage of the report.
        """
        if not self.report_frontpage:
            return {}
        data = self.report_frontpage.get(scheme)
        if not data:
            return {}
        cert_id = data.get("cert_id")
        if not cert_id:
            return {}
        else:
            return {cert_id: 1.0}

    def filename_cert_id(self, scheme: str) -> dict[str, float]:
        """
        Get cert_id candidates from the matches in the report filename and cert filename.
        """
        scheme_filename_rules = rules["cc_filename_cert_id"][scheme]
        if not scheme_filename_rules:
            return {}
        scheme_meta = schemes[scheme]
        results: dict[str, float] = {}
        for fname in (self.report_filename, self.cert_filename):
            if not fname:
                continue

            matches: Counter = Counter()
            for rule in scheme_filename_rules:
                match = re.search(rule, fname)
                if match:
                    try:
                        meta = match.groupdict()
                        cert_id = scheme_meta(meta)
                        matches[cert_id] += 1
                    except Exception:
                        continue
            if not matches:
                continue
            total = max(matches.values())

            for candidate, count in matches.items():
                results.setdefault(candidate, 0)
                results[candidate] += count / total
        # TODO count length in weight
        return results

    def keywords_cert_id(self, scheme: str) -> dict[str, float]:
        """
        Get cert_id candidates from the keywords matches in the report and cert.
        """
        results: dict[str, float] = {}
        for keywords in (self.report_keywords, self.cert_keywords):
            if not keywords:
                continue
            cert_id_matches = keywords.get("cc_cert_id")
            if not cert_id_matches:
                continue

            if scheme not in cert_id_matches:
                continue
            matches: Counter = Counter(cert_id_matches[scheme])
            if not matches:
                continue
            total = max(matches.values())

            for candidate, count in matches.items():
                results.setdefault(candidate, 0)
                results[candidate] += count / total
        # TODO count length in weight
        return results

    def metadata_cert_id(self, scheme: str) -> dict[str, float]:
        """
        Get cert_id candidates from the report metadata.
        """
        scheme_rules = rules["cc_cert_id"][scheme]
        fields = ("/Title", "/Subject")
        results: dict[str, float] = {}
        for metadata in (self.report_metadata, self.cert_metadata):
            if not metadata:
                continue
            matches: Counter = Counter()
            for meta_field in fields:
                field_val = metadata.get(meta_field)
                if not field_val:
                    continue
                for rule in scheme_rules:
                    match = re.search(rule, field_val)
                    if match:
                        cert_id = normalize_match_string(match.group())
                        matches[cert_id] += 1
            if not matches:
                continue
            total = max(matches.values())

            for candidate, count in matches.items():
                results.setdefault(candidate, 0)
                results[candidate] += count / total
        # TODO count length in weight
        return results

    def candidate_cert_ids(self, scheme: str) -> dict[str, float]:
        frontpage_id = self.frontpage_cert_id(scheme)
        metadata_id = self.metadata_cert_id(scheme)
        filename_id = self.filename_cert_id(scheme)
        keywords_id = self.keywords_cert_id(scheme)

        # Join them and weigh them, each is normalized with weights from 0 to 1 (if anything is returned)
        candidates: dict[str, float] = defaultdict(lambda: 0.0)
        # TODO: Add heuristic based on ordering of ids (and extracted year + increment)
        # TODO: Add heuristic based on length
        # TODO: Add heuristic based on id "richness", we want to prefer IDs that have more components.
        # If we cannot canonicalize, just skip that ID.
        for candidate, count in frontpage_id.items():
            try:
                candidates[canonicalize(candidate, scheme)] += count * 1.5
            except Exception:
                continue
        for candidate, count in metadata_id.items():
            try:
                candidates[canonicalize(candidate, scheme)] += count * 1.2
            except Exception:
                continue
        for candidate, count in keywords_id.items():
            try:
                candidates[canonicalize(candidate, scheme)] += count * 1.0
            except Exception:
                continue
        for candidate, count in filename_id.items():
            try:
                candidates[canonicalize(candidate, scheme)] += count * 1.0
            except Exception:
                continue
        return candidates


def extract_pdf_metadata_(cert: CCCertificate | EUCCCertificate, doc_type: DocType) -> CCCertificate | EUCCCertificate:
    doc_state = getattr(cert.state, doc_type.short)
    try:
        metadata = extract_pdf_metadata(doc_state.pdf_path)
        setattr(cert.pdf_data, f"{doc_type.short}_metadata", metadata)
        doc_state.extract_ok = True
    except ValueError:
        doc_state.extract_ok = False
    return cert


def extract_report_pdf_metadata(cert: CCCertificate | EUCCCertificate) -> CCCertificate | EUCCCertificate:
    """
    Extracts metadata from certification report pdf given the certificate. Staticmethod to allow for parallelization.

    :param CCCertificate cert: cert to extract the metadata for.
    :return CCCertificate: the modified certificate with updated state
    """
    return extract_pdf_metadata_(cert, DocType.REPORT)


def extract_st_pdf_metadata(cert: CCCertificate | EUCCCertificate) -> CCCertificate | EUCCCertificate:
    """
    Extracts metadata from security target pdf given the certificate. Staticmethod to allow for parallelization.

    :param CCCertificate cert: cert to extract the metadata for.
    :return CCCertificate: the modified certificate with updated state
    """
    return extract_pdf_metadata_(cert, DocType.TARGET)


def extract_cert_pdf_metadata(cert: CCCertificate | EUCCCertificate) -> CCCertificate | EUCCCertificate:
    """
    Extracts metadata from certificate pdf given the certificate. Staticmethod to allow for parallelization.

    :param CCCertificate cert: cert to extract the metadata for.
    :return CCCertificate: the modified certificate with updated state
    """
    return extract_pdf_metadata_(cert, DocType.REPORT)


def extract_pdf_keywords(cert: CCCertificate | EUCCCertificate, doc_type: DocType) -> CCCertificate | EUCCCertificate:
    doc_state = getattr(cert.state, doc_type.short)
    try:
        keywords = extract_keywords(doc_state.txt_path, cc_rules)
        if keywords is None:
            doc_state.extract_ok = False
        else:
            setattr(cert.pdf_data, f"{doc_type.short}_keywords", keywords)
    except ValueError:
        doc_state.extract_ok = False
    return cert


def extract_report_pdf_keywords(cert: CCCertificate | EUCCCertificate) -> CCCertificate | EUCCCertificate:
    """
    Matches regular expressions in txt obtained from certification report and extracts the matches into attribute.
    Static method to allow for parallelization

    :param CCCertificate cert: certificate to extract the keywords for.
    :return CCCertificate: the modified certificate with extracted keywords.
    """
    return extract_pdf_keywords(cert, DocType.REPORT)


def extract_st_pdf_keywords(cert: CCCertificate | EUCCCertificate) -> CCCertificate | EUCCCertificate:
    """
    Matches regular expressions in txt obtained from security target and extracts the matches into attribute.
    Static method to allow for parallelization

    :param CCCertificate cert: certificate to extract the keywords for.
    :return CCCertificate: the modified certificate with extracted keywords.
    """
    return extract_pdf_keywords(cert, DocType.TARGET)


def extract_cert_pdf_keywords(cert: CCCertificate | EUCCCertificate) -> CCCertificate | EUCCCertificate:
    """
    Matches regular expressions in txt obtained from the certificate and extracts the matches into attribute.
    Static method to allow for parallelization

    :param CCCertificate cert: certificate to extract the keywords for.
    :return CCCertificate: the modified certificate with extracted keywords.
    """
    return extract_pdf_keywords(cert, DocType.CERTIFICATE)


def extract_report_pdf_frontpage(cert: CCCertificate | EUCCCertificate) -> CCCertificate | EUCCCertificate:
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


def convert_pdf(
    cert: CCCertificate | EUCCCertificate, doc_type: DocType, converter: PDFConverter
) -> CCCertificate | EUCCCertificate:
    doc_state = getattr(cert.state, doc_type.short)
    ok_result = converter.convert(doc_state.pdf_path, doc_state.txt_path, doc_state.json_path)
    doc_state.convert_ok = ok_result
    if not ok_result:
        error_msg = f"failed to convert {doc_type.short} pdf->txt"
        logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
    else:
        doc_state.txt_hash = helpers.get_sha256_filepath(doc_state.txt_path)
        if doc_state.json_path.exists():
            doc_state.json_hash = helpers.get_sha256_filepath(doc_state.json_path)
        else:
            doc_state.json_hash = None
    return cert


def download_pdf(cert: CCCertificate | EUCCCertificate, doc_type: DocType):
    link = getattr(cert, f"{doc_type.short}_link")
    doc_state = getattr(cert.state, doc_type.short)
    exit_code = helpers.download_file(link, doc_state.pdf_path, proxy=config.cc_use_proxy) if link else "No link"

    if exit_code != requests.codes.ok:
        error_msg = f"failed to download {doc_type.short} from {link}, code: {exit_code}"
        logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
        doc_state.download_ok = False
    else:
        doc_state.download_ok = True
        doc_state.pdf_hash = helpers.get_sha256_filepath(doc_state.pdf_path)
        setattr(cert.pdf_data, f"{doc_type.short}_filename", unquote_plus(str(urlparse(link).path).split("/")[-1]))
    return cert


def download_pdf_report(cert: CCCertificate | EUCCCertificate) -> CCCertificate | EUCCCertificate:
    """
    Downloads pdf of certification report given the certificate. Staticmethod to allow for parallelization.

    :param CCCertificate cert: cert to download the pdf report for
    :return CCCertificate: returns the modified certificate with updated state
    """
    return download_pdf(cert, DocType.REPORT)


def download_pdf_st(cert: CCCertificate | EUCCCertificate) -> CCCertificate | EUCCCertificate:
    """
    Downloads pdf of security target given the certificate. Staticmethod to allow for parallelization.

    :param CCCertificate cert: cert to download the pdf security target for
    :return CCCertificate: returns the modified certificate with updated state
    """
    return download_pdf(cert, DocType.TARGET)


def download_pdf_cert(cert: CCCertificate | EUCCCertificate) -> CCCertificate | EUCCCertificate:
    """
    Downloads pdf of the certificate. Staticmethod to allow for parallelization.

    :param CCCertificate cert: cert to download the pdf of
    :return CCCertificate: returns the modified certificate with updated state
    """
    return download_pdf(cert, DocType.CERTIFICATE)


def convert_report_pdf(
    cert: CCCertificate | EUCCCertificate, converter: PDFConverter
) -> CCCertificate | EUCCCertificate:
    """
    Converts the pdf certification report to txt, given the certificate. Staticmethod to allow for parallelization.

    :param CCCertificate cert: cert to convert the pdf report for
    :return CCCertificate: the modified certificate with updated state
    """
    return convert_pdf(cert, DocType.REPORT, converter)


def convert_st_pdf(cert: CCCertificate | EUCCCertificate, converter: PDFConverter) -> CCCertificate | EUCCCertificate:
    """
    Converts the pdf security target to txt, given the certificate. Staticmethod to allow for parallelization.

    :param CCCertificate cert: cert to convert the pdf security target for
    :return CCCertificate: the modified certificate with updated state
    """
    return convert_pdf(cert, DocType.TARGET, converter)


def convert_cert_pdf(cert: CCCertificate | EUCCCertificate, converter: PDFConverter) -> CCCertificate | EUCCCertificate:
    """
    Converts the pdf certificate to txt, given the certificate. Staticmethod to allow for parallelization.

    :param CCCertificate cert: cert to convert the certificate for
    :return CCCertificate: the modified certificate with updated state
    """
    return convert_pdf(cert, DocType.CERTIFICATE, converter)


def set_local_paths(
    obj: CCCertificate | EUCCCertificate,
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
        obj.state.report.pdf_path = Path(report_pdf_dir) / (obj.dgst + ".pdf")
    if st_pdf_dir:
        obj.state.st.pdf_path = Path(st_pdf_dir) / (obj.dgst + ".pdf")
    if cert_pdf_dir:
        obj.state.cert.pdf_path = Path(cert_pdf_dir) / (obj.dgst + ".pdf")

    if report_txt_dir:
        obj.state.report.txt_path = Path(report_txt_dir) / (obj.dgst + ".txt")
    if st_txt_dir:
        obj.state.st.txt_path = Path(st_txt_dir) / (obj.dgst + ".txt")
    if cert_txt_dir:
        obj.state.cert.txt_path = Path(cert_txt_dir) / (obj.dgst + ".txt")

    if report_json_dir:
        obj.state.report.json_path = Path(report_json_dir) / (obj.dgst + ".json")
    if st_json_dir:
        obj.state.st.json_path = Path(st_json_dir) / (obj.dgst + ".json")
    if cert_json_dir:
        obj.state.cert.json_path = Path(cert_json_dir) / (obj.dgst + ".json")


def dgst(obj: CCCertificate | EUCCCertificate) -> str:
    """
    Computes the primary key of the sample using first 16 bytes of SHA-256 digest
    """
    if not (obj.name is not None and obj.category is not None):
        raise RuntimeError("Certificate digest can't be computed, because information is missing.")
    return helpers.get_first_16_bytes_sha256(
        "|".join(
            [
                obj.category,
                obj.name,
                sanitization.sanitize_link_fname(obj.report_link) or "None",
                sanitization.sanitize_link_fname(obj.st_link) or "None",
            ]
        )
    )


def actual_sars(obj: CCCertificate | EUCCCertificate) -> set[SAR] | None:
    """
    Computes actual SARs. First, SARs implied by EAL are computed. Then, these are augmented with heuristically extracted SARs.

    :return Optional[Set[SAR]]: Set of actual SARs of a certificate, None if empty
    """
    sars = {}
    if obj.heuristics.eal:
        sars = {x[0]: SAR(x[0], x[1]) for x in SARS_IMPLIED_FROM_EAL[obj.heuristics.eal[:4]]}

    if obj.heuristics.extracted_sars:
        for sar in obj.heuristics.extracted_sars:
            if sar not in sars or sar.level > sars[sar.family].level:
                sars[sar.family] = sar

    return set(sars.values()) if sars else None


def compute_heuristics_cert_lab(obj: CCCertificate | EUCCCertificate) -> None:
    """
    Fills in the heuristically obtained evaluation laboratory into attribute in heuristics class.
    """
    if not obj.pdf_data:
        logger.error("Cannot compute sample lab when pdf files were not processed.")
        return
    obj.heuristics.cert_lab = obj.pdf_data.cert_lab
