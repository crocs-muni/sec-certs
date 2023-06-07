import json
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from sec_certs import constants
from sec_certs.dataset.cc import CCDataset
from sec_certs.sample.cc import CCCertificate


def test_download_and_convert_pdfs(toy_dataset: CCDataset, data_dir: Path):
    template_report_pdf_hashes = {
        "309ac2fd7f2dcf17": "774c41fbba980191ca40ae610b2f61484c5997417b3325b6fd68b345173bde52",
        "8cf86948f02f047d": "533a5995ef8b736cc48cfda30e8aafec77d285511471e0e5a9e8007c8750203a",
        "8a5e6bcda602920c": "e277151e4b279085cd3041ce914ffb3942b43e5ace911c557ad6b8ed764a4ece",
    }

    template_st_pdf_hashes = {
        "309ac2fd7f2dcf17": "b9a45995d9e40b2515506bbf5945e806ef021861820426c6d0a6a074090b47a9",
        "8cf86948f02f047d": "3c8614338899d956e9e56f1aa88d90e37df86f3310b875d9d14ec0f71e4759be",
        "8a5e6bcda602920c": "fcee91f09bb72a6526a1f94d0ab754a6db3fbe3ba5773cd372df19788bb25292",
    }

    with TemporaryDirectory() as td:
        toy_dataset.copy_dataset(td)
        toy_dataset.download_all_artifacts()

        if not (
            toy_dataset["309ac2fd7f2dcf17"].state.report_download_ok
            or toy_dataset["309ac2fd7f2dcf17"].state.st_download_ok
            or toy_dataset["8cf86948f02f047d"].state.report_download_ok
            or toy_dataset["8cf86948f02f047d"].state.st_download_ok
            or toy_dataset["8a5e6bcda602920c"].state.report_download_ok
            or toy_dataset["8a5e6bcda602920c"].state.st_download_ok
        ):
            pytest.xfail(reason="Fail due to error during download")

        toy_dataset.convert_all_pdfs()

        for cert in toy_dataset:
            assert cert.state.report_pdf_hash == template_report_pdf_hashes[cert.dgst]
            assert cert.state.st_pdf_hash == template_st_pdf_hashes[cert.dgst]
            assert not cert.state.report_convert_garbage
            assert not cert.state.st_convert_garbage
            assert cert.state.report_convert_ok
            assert cert.state.st_convert_ok
            assert cert.state.report_txt_path.exists()
            assert cert.state.st_txt_path.exists()

        template_report_txt_path = data_dir / "report_309ac2fd7f2dcf17.txt"
        template_st_txt_path = data_dir / "target_309ac2fd7f2dcf17.txt"
        assert (
            abs(toy_dataset["309ac2fd7f2dcf17"].state.st_txt_path.stat().st_size - template_st_txt_path.stat().st_size)
            < 1000
        )
        assert (
            abs(
                toy_dataset["309ac2fd7f2dcf17"].state.report_txt_path.stat().st_size
                - template_report_txt_path.stat().st_size
            )
            < 1000
        )


def test_dataset_to_json(toy_dataset: CCDataset, data_dir: Path, tmp_path: Path):
    toy_dataset.to_json(tmp_path / "dset.json")

    with (tmp_path / "dset.json").open("r") as handle:
        data = json.load(handle)

    with (data_dir / "toy_dataset.json").open("r") as handle:
        template_data = json.load(handle)

    del data["timestamp"]
    del template_data["timestamp"]
    assert data == template_data


def test_dataset_from_json(toy_dataset: CCDataset, data_dir: Path, tmp_path):
    assert toy_dataset == CCDataset.from_json(data_dir / "toy_dataset.json")

    compressed_path = tmp_path / "dset.json.gz"
    toy_dataset.to_json(compressed_path, compress=True)
    decompressed_dataset = CCDataset.from_json(compressed_path, is_compressed=True)
    assert toy_dataset == decompressed_dataset


def test_build_empty_dataset():
    with TemporaryDirectory() as tmp_dir:
        dset = CCDataset({}, Path(tmp_dir), "sample_dataset", "sample dataset description")
        dset.get_certs_from_web(to_download=False, get_archived=False, get_active=False)
    assert len(dset) == 0
    assert dset.state.meta_sources_parsed
    assert not dset.state.artifacts_downloaded
    assert not dset.state.pdfs_converted
    assert not dset.state.certs_analyzed


def test_build_dataset(data_dir: Path, cert_one: CCCertificate, toy_dataset: CCDataset):
    with TemporaryDirectory() as tmp_dir:
        dataset_path = Path(tmp_dir)
        (dataset_path / "web").mkdir()
        shutil.copyfile(data_dir / "cc_products_active.csv", dataset_path / "web" / "cc_products_active.csv")
        shutil.copyfile(data_dir / "cc_products_active.html", dataset_path / "web" / "cc_products_active.html")

        dset = CCDataset({}, dataset_path, "sample_dataset", "sample dataset description")
        dset.get_certs_from_web(
            keep_metadata=False, to_download=False, get_archived=False, get_active=True, update_json=False
        )

        assert len(list(dataset_path.iterdir())) == 0
        assert len(dset) == 3
        assert cert_one in dset
        assert dset == toy_dataset


def test_process_pp_dataset(toy_dataset: CCDataset):
    with TemporaryDirectory() as tmp_dir:
        toy_dataset.copy_dataset(tmp_dir)
        toy_dataset.process_protection_profiles()
        assert toy_dataset.pp_dataset_path.exists()
        assert toy_dataset.pp_dataset_path.stat().st_size > constants.MIN_CC_PP_DATASET_SIZE


@pytest.mark.xfail(reason="May fail due to error on CC server")
def test_download_csv_html_files():
    with TemporaryDirectory() as tmp_dir:
        dset = CCDataset({}, Path(tmp_dir), "sample_dataset", "sample dataset description")
        dset._download_csv_html_resources(get_active=True, get_archived=False)

        for x in dset.active_html_tuples:
            assert x[1].exists()
            assert x[1].stat().st_size >= constants.MIN_CC_HTML_SIZE
        for x in dset.active_csv_tuples:
            assert x[1].exists()
            assert x[1].stat().st_size >= constants.MIN_CC_CSV_SIZE


def test_to_pandas(toy_dataset: CCDataset):
    df = toy_dataset.to_pandas()
    assert df.shape == (len(toy_dataset), len(CCCertificate.pandas_columns))
    assert df.index.name == "dgst"
    assert set(df.columns) == (set(CCCertificate.pandas_columns).union({"year_from"})) - {"dgst"}
