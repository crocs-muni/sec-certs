from typing import Literal
from urllib.parse import unquote_plus, urlparse

import requests

from sec_certs.cert_rules import cc_rules
from sec_certs.configuration import config
from sec_certs.converter import PDFConverter
from sec_certs.dataset.dataset import logger
from sec_certs.sample.cc import CCCertificate
from sec_certs.utils import helpers
from sec_certs.utils.extract import extract_keywords, scheme_frontpage_functions
from sec_certs.utils.pdf import extract_pdf_metadata


def extract_pdf_metadata_(cert: CCCertificate, doc_type: Literal["report", "st", "cert"]) -> CCCertificate:
    doc_state = getattr(cert.state, doc_type)
    try:
        metadata = extract_pdf_metadata(doc_state.pdf_path)
        setattr(cert.pdf_data, f"{doc_type}_metadata", metadata)
        doc_state.extract_ok = True
    except ValueError:
        doc_state.extract_ok = False
    return cert


def extract_pdf_keywords(cert: CCCertificate, doc_type: Literal["report", "st", "cert"]) -> CCCertificate:
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


def extract_report_pdf_metadata(cert: CCCertificate) -> CCCertificate:
    """
    Extracts metadata from certification report pdf given the certificate. Staticmethod to allow for parallelization.

    :param CCCertificate cert: cert to extract the metadata for.
    :return CCCertificate: the modified certificate with updated state
    """
    return extract_pdf_metadata_(cert, "report")


def extract_st_pdf_metadata(cert: CCCertificate) -> CCCertificate:
    """
    Extracts metadata from security target pdf given the certificate. Staticmethod to allow for parallelization.

    :param CCCertificate cert: cert to extract the metadata for.
    :return CCCertificate: the modified certificate with updated state
    """
    return extract_pdf_metadata_(cert, "st")


def extract_cert_pdf_metadata(cert: CCCertificate) -> CCCertificate:
    """
    Extracts metadata from certificate pdf given the certificate. Staticmethod to allow for parallelization.

    :param CCCertificate cert: cert to extract the metadata for.
    :return CCCertificate: the modified certificate with updated state
    """
    return extract_pdf_metadata_(cert, "cert")


def extract_report_pdf_keywords(cert: CCCertificate) -> CCCertificate:
    """
    Matches regular expressions in txt obtained from certification report and extracts the matches into attribute.
    Static method to allow for parallelization

    :param CCCertificate cert: certificate to extract the keywords for.
    :return CCCertificate: the modified certificate with extracted keywords.
    """
    return extract_pdf_keywords(cert, "report")


def extract_st_pdf_keywords(cert: CCCertificate) -> CCCertificate:
    """
    Matches regular expressions in txt obtained from security target and extracts the matches into attribute.
    Static method to allow for parallelization

    :param CCCertificate cert: certificate to extract the keywords for.
    :return CCCertificate: the modified certificate with extracted keywords.
    """
    return extract_pdf_keywords(cert, "st")


def extract_cert_pdf_keywords(cert: CCCertificate) -> CCCertificate:
    """
    Matches regular expressions in txt obtained from the certificate and extracts the matches into attribute.
    Static method to allow for parallelization

    :param CCCertificate cert: certificate to extract the keywords for.
    :return CCCertificate: the modified certificate with extracted keywords.
    """
    return extract_pdf_keywords(cert, "cert")


def extract_report_pdf_frontpage(cert: CCCertificate) -> CCCertificate:
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
    cert: CCCertificate, doc_type: Literal["report", "st", "cert"], converter: PDFConverter
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


def convert_report_pdf(cert: CCCertificate, converter: PDFConverter) -> CCCertificate:
    """
    Converts the pdf certification report to txt, given the certificate. Staticmethod to allow for parallelization.

    :param CCCertificate cert: cert to convert the pdf report for
    :return CCCertificate: the modified certificate with updated state
    """
    return convert_pdf(cert, "report", converter)


def convert_st_pdf(cert: CCCertificate, converter: PDFConverter) -> CCCertificate:
    """
    Converts the pdf security target to txt, given the certificate. Staticmethod to allow for parallelization.

    :param CCCertificate cert: cert to convert the pdf security target for
    :return CCCertificate: the modified certificate with updated state
    """
    return convert_pdf(cert, "st", converter)


def convert_cert_pdf(cert: CCCertificate, converter: PDFConverter) -> CCCertificate:
    """
    Converts the pdf certificate to txt, given the certificate. Staticmethod to allow for parallelization.

    :param CCCertificate cert: cert to convert the certificate for
    :return CCCertificate: the modified certificate with updated state
    """
    return convert_pdf(cert, "cert", converter)


def download_pdf(cert: CCCertificate, doc_type: Literal["report", "st", "cert"]):
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


def download_pdf_report(cert: CCCertificate) -> CCCertificate:
    """
    Downloads pdf of certification report given the certificate. Staticmethod to allow for parallelization.

    :param CCCertificate cert: cert to download the pdf report for
    :return CCCertificate: returns the modified certificate with updated state
    """
    return download_pdf(cert, "report")


def download_pdf_st(cert: CCCertificate) -> CCCertificate:
    """
    Downloads pdf of security target given the certificate. Staticmethod to allow for parallelization.

    :param CCCertificate cert: cert to download the pdf security target for
    :return CCCertificate: returns the modified certificate with updated state
    """
    return download_pdf(cert, "st")


def download_pdf_cert(cert: CCCertificate) -> CCCertificate:
    """
    Downloads pdf of the certificate. Staticmethod to allow for parallelization.

    :param CCCertificate cert: cert to download the pdf of
    :return CCCertificate: returns the modified certificate with updated state
    """
    return download_pdf(cert, "cert")
