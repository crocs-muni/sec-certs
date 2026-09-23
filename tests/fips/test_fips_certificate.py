from __future__ import annotations

import json
import shutil
from collections.abc import Generator
from importlib.resources import as_file, files
from pathlib import Path

import pytest
import tests.data.fips.certificate
import tests.data.fips.dataset

from sec_certs.configuration import config
from sec_certs.dataset.fips import FIPSDataset
from sec_certs.sample.fips import FIPSCertificate
from sec_certs.serialization.schemas import validator


@pytest.fixture(scope="module")
def data_dir() -> Generator[Path, None, None]:
    with as_file(files(tests.data.fips.certificate)) as path:
        yield path


@pytest.fixture
def certificate(tmp_path_factory) -> FIPSCertificate:
    tmp_dir = tmp_path_factory.mktemp("dset")

    with as_file(files(tests.data.fips.dataset)) as dataset_path:
        shutil.copytree(dataset_path, tmp_dir, dirs_exist_ok=True)

    fips_dset = FIPSDataset.from_json(tmp_dir / "toy_dataset.json")

    crt = fips_dset["184097a88a9b4ad9"]
    fips_dset.certs = {crt.dgst: crt}
    fips_dset.download_all_artifacts()
    fips_dset.convert_all_pdfs()

    return crt


def test_extract_module(certificate: FIPSCertificate):
    certificate.state.module.extract_ok = True
    FIPSCertificate.parse_html_module(certificate)
    assert certificate.state.module.extract_ok


def test_prune_reference_ids_drops_algorithms_and_certlike(monkeypatch):
    """The contract the extracted algorithm ids exist to serve: they remove false cert references."""
    monkeypatch.setattr(config, "always_false_positive_fips_cert_id_threshold", 40)
    cert = FIPSCertificate(3095)
    cert.heuristics.algorithms = {"#3093", "AES#3094"}
    cert.pdf_data.keywords = {"fips_certlike": {"Certlike": {"Cert. #3096": 1}}}

    pruned = cert._prune_reference_ids_variable({"3093", "3094", "3096", "3097", "12", "3095"})

    # 3093/3094 are algorithms, 3096 is certlike, 12 is below the threshold, 3095 is the cert itself.
    assert pruned == {"3097"}


def test_algorithm_numbers_ignore_ids_without_a_hash():
    """Why extracted ids are canonicalized to '#<number>': without the hash they never reach pruning."""
    cert = FIPSCertificate(3095)
    cert.heuristics.algorithms = {"3093", "Cert. 3094"}

    assert cert.heuristics.algorithm_numbers == set()

    cert.heuristics.algorithms = {"#3093", "#A3094"}

    assert cert.heuristics.algorithm_numbers == {"3093", "3094"}


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


def test_schema_validation(data_dir: Path):
    with (data_dir / "fictional_cert.json").open("r") as cert:
        v = validator("http://sec-certs.org/schemas/fips_certificate.json")
        v.validate(json.load(cert))
