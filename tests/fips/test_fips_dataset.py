from __future__ import annotations

import json
import shutil
from collections.abc import Generator
from importlib import resources
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
import tests.data.fips.dataset

from sec_certs import constants
from sec_certs.configuration import config
from sec_certs.dataset.fips import FIPSDataset
from sec_certs.sample.fips import FIPSCertificate
from sec_certs.serialization.schemas import validator
from sec_certs.utils import helpers


@pytest.fixture(scope="module")
def data_dir() -> Generator[Path, None, None]:
    with resources.path(tests.data.fips.dataset, "") as path:
        yield path


def test_dataset_to_json(toy_dataset: FIPSDataset, data_dir: Path, tmp_path: Path):
    toy_dataset.to_json(tmp_path / "dset.json")

    with (tmp_path / "dset.json").open("r") as handle:
        data = json.load(handle)

    with (data_dir / "toy_dataset.json").open("r") as handle:
        template_data = json.load(handle)

    del data["timestamp"]
    del template_data["timestamp"]
    del data["state"]["sec_certs_version"]
    del template_data["state"]["sec_certs_version"]
    assert data == template_data


@pytest.mark.remote
def test_from_web():
    dset = FIPSDataset.from_web()
    assert len(dset) > 4000


@pytest.mark.remote
def test_archive_fits():
    fsize = helpers.query_file_size(config.fips_latest_full_archive)
    tmpdir = helpers.tempdir_for(fsize)
    assert tmpdir is not None


def test_dataset_from_json(toy_dataset: FIPSDataset, data_dir: Path, tmp_path: Path):
    assert toy_dataset == FIPSDataset.from_json(data_dir / "toy_dataset.json")

    compressed_path = tmp_path / "dset.json.gz"
    toy_dataset.to_json(compressed_path, compress=True)
    decompressed_dataset = FIPSDataset.from_json(compressed_path, is_compressed=True)
    assert toy_dataset == decompressed_dataset


def test_build_empty_dataset():
    with TemporaryDirectory() as tmp_dir:
        dset = FIPSDataset(root_dir=tmp_dir)
    assert len(dset) == 0
    assert not dset.state.meta_sources_parsed
    assert not dset.state.artifacts_downloaded
    assert not dset.state.pdfs_converted
    assert not dset.state.certs_analyzed


def test_build_dataset(data_dir: Path, toy_dataset: FIPSDataset):
    with TemporaryDirectory() as tmp_dir:
        dataset_path = Path(tmp_dir)
        (dataset_path / "web").mkdir()
        shutil.copyfile(data_dir / "fips_modules_active.html", dataset_path / "web" / "fips_modules_active.html")
        shutil.copyfile(
            data_dir / "fips_modules_historical.html", dataset_path / "web" / "fips_modules_historical.html"
        )
        shutil.copyfile(data_dir / "fips_modules_revoked.html", dataset_path / "web" / "fips_modules_revoked.html")

        dset = FIPSDataset(root_dir=dataset_path)
        dset.get_certs_from_web(to_download=False)

        assert len(dset) == len(toy_dataset)
        assert set(dset.certs.keys()) == set(toy_dataset.certs.keys())


@pytest.mark.xfail(reason="May fail due to error on FIPS server.")
def test_download_meta_html_files():
    with TemporaryDirectory() as tmp_dir:
        dset = FIPSDataset(root_dir=Path(tmp_dir))
        dset.web_dir.mkdir()
        dset._download_html_resources()

        assert (dset.web_dir / "fips_modules_active.html").exists()
        assert (dset.web_dir / "fips_modules_active.html").stat().st_size > constants.MIN_FIPS_HTML_SIZE
        assert (dset.web_dir / "fips_modules_historical.html").exists()
        assert (dset.web_dir / "fips_modules_historical.html").stat().st_size > constants.MIN_FIPS_HTML_SIZE
        assert (dset.web_dir / "fips_modules_revoked.html").exists()
        assert (dset.web_dir / "fips_modules_revoked.html").stat().st_size > constants.MIN_FIPS_HTML_SIZE


def test_download_and_convert_artifacts(toy_dataset: FIPSDataset, data_dir: Path):
    crt = toy_dataset["184097a88a9b4ad9"]
    toy_dataset.certs = {crt.dgst: crt}
    with TemporaryDirectory() as tmp_dir:
        toy_dataset.copy_dataset(tmp_dir)
        toy_dataset.download_all_artifacts()

        if not crt.state.policy_download_ok or not crt.state.module_download_ok:
            pytest.xfail(reason="Fail due to error during download")

        toy_dataset.convert_all_pdfs()

        assert crt.state.policy_convert_ok
        assert crt.state.policy_pdf_hash == "36b63890182f0aed29b305a0b4acc0d70b657262516f4be69138c70c2abdb1f1"
        assert crt.state.policy_txt_path.exists()
        assert crt.state.policy_json_path.exists()

        template_policy_txt_path = data_dir / "template_policy_184097a88a9b4ad9.txt"
        assert abs(crt.state.policy_txt_path.stat().st_size - template_policy_txt_path.stat().st_size) < 1000


def test_to_pandas(toy_dataset: FIPSDataset):
    df = toy_dataset.to_pandas()
    assert df.shape == (len(toy_dataset), len(FIPSCertificate.pandas_columns))
    assert df.index.name == "dgst"
    assert set(df.columns) == set(FIPSCertificate.pandas_columns).union({"year_from"}) - {"dgst"}


def test_schema_validate(toy_dataset: FIPSDataset):
    with TemporaryDirectory() as tmp_dir:
        single_v = validator("http://sec-certs.org/schemas/fips_certificate.json")
        for cert in toy_dataset:
            fname = Path(tmp_dir) / (cert.dgst + ".json")
            cert.to_json(fname)
            with fname.open("r") as handle:
                single_v.validate(json.load(handle))

        dset_v = validator("http://sec-certs.org/schemas/fips_dataset.json")
        fname = Path(tmp_dir) / "dset.json"
        toy_dataset.to_json(fname)
        with fname.open("r") as handle:
            dset_v.validate(json.load(handle))
