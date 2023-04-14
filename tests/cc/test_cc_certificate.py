import json
from pathlib import Path

from sec_certs.sample import CCCertificate


def test_extract_metadata(vulnerable_certificate: CCCertificate):
    vulnerable_certificate.state.st_extract_ok = True
    CCCertificate.extract_st_pdf_metadata(vulnerable_certificate)
    assert vulnerable_certificate.state.st_extract_ok

    vulnerable_certificate.state.report_extract_ok = True
    CCCertificate.extract_report_pdf_metadata(vulnerable_certificate)
    assert vulnerable_certificate.state.report_extract_ok


def test_extract_frontpage(vulnerable_certificate: CCCertificate):
    vulnerable_certificate.state.st_extract_ok = True
    CCCertificate.extract_st_pdf_frontpage(vulnerable_certificate)
    assert vulnerable_certificate.state.st_extract_ok

    vulnerable_certificate.state.report_extract_ok = True
    CCCertificate.extract_report_pdf_frontpage(vulnerable_certificate)
    assert vulnerable_certificate.state.report_extract_ok


def test_keyword_extraction(vulnerable_certificate: CCCertificate):
    vulnerable_certificate.state.st_extract_ok = True
    CCCertificate.extract_st_pdf_keywords(vulnerable_certificate)
    assert vulnerable_certificate.state.st_extract_ok

    vulnerable_certificate.state.report_extract_ok = True
    CCCertificate.extract_report_pdf_keywords(vulnerable_certificate)
    assert vulnerable_certificate.state.report_extract_ok


def test_cert_link_escaping(cert_one: CCCertificate):
    assert (
        cert_one.report_link
        == "https://www.commoncriteriaportal.org/files/epfiles/Certification%20Report%20-%20NetIQ®%20Identity%20Manager%204.7.pdf"
    )


def test_cert_to_json(cert_two: CCCertificate, tmp_path: Path, cert_data_dir: Path):
    cert_two.to_json(tmp_path / "crt_two.json")

    with (tmp_path / "crt_two.json").open("r") as handle:
        data = json.load(handle)

    with (cert_data_dir / "fictional_cert.json").open("r") as handle:
        template_data = json.load(handle)

    assert data == template_data


def test_cert_from_json(cert_two: CCCertificate, cert_data_dir: Path):
    crt = CCCertificate.from_json(cert_data_dir / "fictional_cert.json")
    assert cert_two == crt
