from typing import Literal

from sec_certs.cert_rules import cc_rules
from sec_certs.dataset.dataset import logger
from sec_certs.sample.cc import CCCertificate
from sec_certs.utils import helpers
from sec_certs.utils.extract import extract_keywords, scheme_frontpage_functions
from sec_certs.utils.pdf import convert_pdf_file, extract_pdf_metadata


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

def convert_pdf(cert: CCCertificate, doc_type: Literal["report", "st", "cert"]) -> CCCertificate:
    doc_state = getattr(cert.state, doc_type)
    ocr_done, ok_result = convert_pdf_file(doc_state.pdf_path, doc_state.txt_path)
    # If OCR was done the result was garbage
    doc_state.convert_garbage = ocr_done
    # And put the whole result into convert_ok
    doc_state.convert_ok = ok_result
    if not ok_result:
        error_msg = f"failed to convert {doc_type} pdf->txt"
        logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
    else:
        doc_state.txt_hash = helpers.get_sha256_filepath(doc_state.txt_path)
    return cert

def convert_report_pdf(cert: CCCertificate) -> CCCertificate:
    """
    Converts the pdf certification report to txt, given the certificate. Staticmethod to allow for parallelization.

    :param CCCertificate cert: cert to convert the pdf report for
    :return CCCertificate: the modified certificate with updated state
    """
    return convert_pdf(cert, "report")

def convert_st_pdf(cert: CCCertificate) -> CCCertificate:
    """
    Converts the pdf security target to txt, given the certificate. Staticmethod to allow for parallelization.

    :param CCCertificate cert: cert to convert the pdf security target for
    :return CCCertificate: the modified certificate with updated state
    """
    return convert_pdf(cert, "st")

def convert_cert_pdf(cert: CCCertificate) -> CCCertificate:
    """
    Converts the pdf certificate to txt, given the certificate. Staticmethod to allow for parallelization.

    :param CCCertificate cert: cert to convert the certificate for
    :return CCCertificate: the modified certificate with updated state
    """
    return convert_pdf(cert, "cert")
