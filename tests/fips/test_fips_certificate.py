from __future__ import annotations

import json
import shutil
from collections.abc import Generator
from importlib import resources
from pathlib import Path

import pytest
import tests.data.fips.certificate
import tests.data.fips.dataset

from sec_certs.dataset.fips import FIPSDataset
from sec_certs.sample.fips import FIPSCertificate


@pytest.fixture(scope="module")
def data_dir() -> Generator[Path, None, None]:
    with resources.path(tests.data.fips.certificate, "") as path:
        yield path


@pytest.fixture
def certificate(tmp_path_factory) -> FIPSCertificate:
    tmp_dir = tmp_path_factory.mktemp("dset")

    with resources.path(tests.data.fips.dataset, "") as dataset_path:
        shutil.copytree(dataset_path, tmp_dir, dirs_exist_ok=True)

    fips_dset = FIPSDataset.from_json(tmp_dir / "toy_dataset.json")

    crt = fips_dset["184097a88a9b4ad9"]
    fips_dset.certs = {crt.dgst: crt}
    fips_dset.download_all_artifacts()
    fips_dset.convert_all_pdfs()

    return crt


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


def test_cert_to_json(certificate: FIPSCertificate, tmp_path: Path, data_dir: Path):
    certificate.to_json(tmp_path / "crt.json")

    with (tmp_path / "crt.json").open("r") as handle:
        data = json.load(handle)

    with (data_dir / "fictional_cert.json").open("r") as handle:
        template_data = json.load(handle)

    assert template_data == data


def test_cert_from_json(certificate: FIPSCertificate, data_dir: Path):
    crt = FIPSCertificate.from_json(data_dir / "fictional_cert.json")
    assert certificate == crt
