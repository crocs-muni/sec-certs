import json
import shutil
from datetime import date
from pathlib import Path

import pytest

import tests.data.cc.analysis
import tests.data.cc.certificate
from sec_certs.dataset import CCDataset
from sec_certs.sample import CCCertificate
from sec_certs.sample.protection_profile import ProtectionProfile


@pytest.fixture(scope="module")
def data_dir() -> Path:
    return Path(tests.data.cc.certificate.__path__[0])


@pytest.fixture(scope="module")
def vulnerable_certificate(tmp_path_factory) -> CCCertificate:
    tmp_dir = tmp_path_factory.mktemp("dset")
    dset_json_path = Path(tests.data.cc.analysis.__path__[0]) / "vulnerable_dataset.json"
    data_dir_path = dset_json_path.parent
    shutil.copytree(data_dir_path, tmp_dir, dirs_exist_ok=True)
    cc_dset = CCDataset.from_json(tmp_dir / "vulnerable_dataset.json")
    cc_dset.download_all_artifacts()
    cc_dset.convert_all_pdfs()

    return list(cc_dset.certs.values())[0]


@pytest.fixture(scope="module")
def cert_one() -> CCCertificate:
    return CCCertificate(
        "active",
        "Access Control Devices and Systems",
        "NetIQ Identity Manager 4.7",
        "NetIQ Corporation",
        "SE",
        {"ALC_FLR.2", "EAL3+"},
        date(2020, 6, 15),
        date(2025, 6, 15),
        "https://www.commoncriteriaportal.org/files/epfiles/Certification%20Report%20-%20NetIQ®%20Identity%20Manager%204.7.pdf",
        "https://www.commoncriteriaportal.org/files/epfiles/ST%20-%20NetIQ%20Identity%20Manager%204.7.pdf",
        "https://www.commoncriteriaportal.org/files/epfiles/Certifikat%20CCRA%20-%20NetIQ%20Identity%20Manager%204.7_signed.pdf",
        "https://www.netiq.com/",
        set(),
        set(),
        None,
        None,
        None,
    )


@pytest.fixture(scope="module")
def cert_two() -> CCCertificate:
    pp = ProtectionProfile("sample_pp", None, pp_link="https://sample.pp")
    update = CCCertificate.MaintenanceReport(
        date(1900, 1, 1), "Sample maintenance", "https://maintenance.up", "https://maintenance.up"
    )

    return CCCertificate(
        "archived",
        "Sample category",
        "Sample certificate name",
        "Sample manufacturer",
        "Sample scheme",
        {"Sample security level"},
        date(1900, 1, 2),
        date(1900, 1, 3),
        "https://path.to/report/link",
        "https://path.to/st/link",
        "https://path.to/cert/link",
        "https://path.to/manufacturer/web",
        {pp},
        {update},
        None,
        None,
        None,
    )


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
