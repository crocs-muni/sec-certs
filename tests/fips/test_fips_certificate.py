import json
from pathlib import Path

from sec_certs.sample.fips import FIPSCertificate


def test_extract_metadata(certificate: FIPSCertificate):
    pass


def test_extract_module(certificate: FIPSCertificate):
    certificate.state.module_extract_ok = True
    FIPSCertificate.parse_html_module(certificate)
    assert certificate.state.module_extract_ok


def test_extract_frontpage():
    pass


def test_keyword_extraction():
    pass


def test_cert_to_json(certificate: FIPSCertificate, tmp_path: Path, cert_data_dir: Path):
    certificate.to_json(tmp_path / "crt.json")

    with (tmp_path / "crt.json").open("r") as handle:
        data = json.load(handle)

    with (cert_data_dir / "fictional_cert.json").open("r") as handle:
        template_data = json.load(handle)

    assert template_data == data


def test_cert_from_json(certificate: FIPSCertificate, cert_data_dir: Path):
    crt = FIPSCertificate.from_json(cert_data_dir / "fictional_cert.json")
    assert certificate == crt
