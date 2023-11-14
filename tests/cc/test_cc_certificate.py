import json
import shutil
from collections.abc import Generator
from importlib import resources
from pathlib import Path

import pytest
import tests.data.cc.analysis
import tests.data.cc.certificate

from sec_certs.dataset import CCDataset
from sec_certs.sample import CCCertificate


@pytest.fixture(scope="module")
def data_dir() -> Generator[Path, None, None]:
    with resources.path(tests.data.cc.certificate, "") as path:
        yield path


@pytest.fixture(scope="module")
def vulnerable_certificate(tmp_path_factory) -> CCCertificate:
    tmp_dir = tmp_path_factory.mktemp("dset")

    with resources.path(tests.data.cc.analysis, "") as analysis_path:
        shutil.copytree(analysis_path, tmp_dir, dirs_exist_ok=True)
    cc_dset = CCDataset.from_json(tmp_dir / "vulnerable_dataset.json")
    cc_dset.download_all_artifacts()
    cc_dset.convert_all_pdfs()

    return list(cc_dset.certs.values())[0]


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


def test_cert_to_json(cert_two: CCCertificate, tmp_path: Path, data_dir: Path):
    cert_two.to_json(tmp_path / "crt_two.json")

    with (tmp_path / "crt_two.json").open("r") as handle:
        data = json.load(handle)

    with (data_dir / "fictional_cert.json").open("r") as handle:
        template_data = json.load(handle)

    assert data == template_data


def test_cert_from_json(cert_two: CCCertificate, data_dir: Path):
    crt = CCCertificate.from_json(data_dir / "fictional_cert.json")
    assert cert_two == crt
