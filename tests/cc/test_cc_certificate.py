import json
import shutil
from collections.abc import Generator
from importlib.resources import as_file, files
from pathlib import Path

import pytest
import tests.data.cc.analysis
import tests.data.cc.certificate

from sec_certs.dataset import CCDataset
from sec_certs.sample import CCCertificate
from sec_certs.sample.cc_eucc_mixin import CC_EUCC_SampleMixin
from sec_certs.serialization.schemas import validator


@pytest.fixture(scope="module")
def data_dir() -> Generator[Path, None, None]:
    with as_file(files(tests.data.cc.certificate)) as path:
        yield path


@pytest.fixture(scope="module")
def vulnerable_certificate(tmp_path_factory) -> CCCertificate:
    tmp_dir = tmp_path_factory.mktemp("dset")

    with as_file(files(tests.data.cc.analysis)) as analysis_path:
        shutil.copytree(analysis_path, tmp_dir, dirs_exist_ok=True)
    cc_dset = CCDataset.from_json(tmp_dir / "vulnerable_dataset.json")
    cc_dset.download_all_artifacts()
    cc_dset.convert_all_pdfs()

    return list(cc_dset.certs.values())[0]


def test_extract_metadata(vulnerable_certificate: CCCertificate):
    vulnerable_certificate.state.st.extract_ok = True
    CC_EUCC_SampleMixin.extract_st_pdf_metadata(vulnerable_certificate)
    assert vulnerable_certificate.state.st.extract_ok

    vulnerable_certificate.state.report.extract_ok = True
    CC_EUCC_SampleMixin.extract_report_pdf_metadata(vulnerable_certificate)
    assert vulnerable_certificate.state.report.extract_ok


def test_extract_frontpage(vulnerable_certificate: CCCertificate):
    vulnerable_certificate.state.report.extract_ok = True
    CC_EUCC_SampleMixin.extract_report_pdf_frontpage(vulnerable_certificate)
    assert vulnerable_certificate.state.report.extract_ok


def test_keyword_extraction(vulnerable_certificate: CCCertificate):
    vulnerable_certificate.state.st.extract_ok = True
    CC_EUCC_SampleMixin.extract_st_pdf_keywords(vulnerable_certificate)
    assert vulnerable_certificate.state.st.extract_ok

    vulnerable_certificate.state.report.extract_ok = True
    CC_EUCC_SampleMixin.extract_report_pdf_keywords(vulnerable_certificate)
    assert vulnerable_certificate.state.report.extract_ok


def test_cert_link_escaping(cert_one: CCCertificate):
    assert (
        cert_one.report_link
        == "https://www.commoncriteriaportal.org/nfs/ccpfiles/files/epfiles/Certification%20Report%20-%20NetIQ®%20Identity%20Manager%204.7.pdf"
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


def test_cert_old_dgst(cert_one: CCCertificate):
    assert cert_one.old_dgst == "309ac2fd7f2dcf17"
    with pytest.raises(RuntimeError):
        cert_one.report_link = None
        cert_one.old_dgst


def test_cert_dgst(cert_one: CCCertificate):
    assert cert_one.dgst == "e3dcf91ef38ddbf0"
    cert_one.name = None
    with pytest.raises(RuntimeError):
        cert_one.dgst


def test_cert_older_dgst(cert_one: CCCertificate):
    assert cert_one.older_dgst == "916f4d199f78d70c"
    cert_one.report_link = None
    with pytest.raises(RuntimeError):
        cert_one.older_dgst


def test_schema_validation(data_dir: Path):
    with (data_dir / "fictional_cert.json").open("r") as cert:
        v = validator("http://sec-certs.org/schemas/cc_certificate.json")
        v.validate(json.load(cert))
