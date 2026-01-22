import json
import shutil
from importlib.resources import as_file, files
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
import tests.data.protection_profiles
from tests.conftest import compare_to_template, get_converters

from sec_certs import constants
from sec_certs.converter import PDFConverter
from sec_certs.dataset.protection_profile import ProtectionProfileDataset


def test_dataset_from_json(toy_pp_dataset: ProtectionProfileDataset, pp_data_dir: Path, tmp_path: Path):
    toy_pp_dataset.to_json(tmp_path / "dset.json")
    with (tmp_path / "dset.json").open("r") as handle:
        data = json.load(handle)

    with (pp_data_dir / "dataset.json").open("r") as handle:
        template_data = json.load(handle)

    del data["timestamp"]
    del template_data["timestamp"]
    del data["state"]["sec_certs_version"]
    del template_data["state"]["sec_certs_version"]
    assert data == template_data


def test_dataset_to_json(toy_pp_dataset: ProtectionProfileDataset, pp_data_dir: Path, tmp_path: Path):
    assert toy_pp_dataset == ProtectionProfileDataset.from_json(pp_data_dir / "dataset.json")
    compressed_path = tmp_path / "dset.json.gz"
    toy_pp_dataset.to_json(compressed_path, compress=True)
    decompressed_dataset = ProtectionProfileDataset.from_json(compressed_path, is_compressed=True)
    assert toy_pp_dataset == decompressed_dataset


def test_build_empty_dataset():
    with TemporaryDirectory() as tmp_dir:
        dset = ProtectionProfileDataset(root_dir=Path(tmp_dir))
        dset.get_certs_from_web(to_download=False, get_archived=False, get_active=False, get_collaborative=False)

    assert len(dset) == 0
    assert dset.state.meta_sources_parsed
    assert not dset.state.auxiliary_datasets_processed
    assert not dset.state.artifacts_downloaded
    assert not dset.state.pdfs_converted
    assert not dset.state.certs_analyzed


def test_get_certs_from_web(pp_data_dir: Path, toy_pp_dataset: ProtectionProfileDataset):
    with TemporaryDirectory() as tmp_dir:
        dataset_path = Path(tmp_dir)
        (dataset_path / "web").mkdir()
        shutil.copyfile(pp_data_dir / "pp_active.html", dataset_path / "web/pp_active.html")

        dset = ProtectionProfileDataset(root_dir=dataset_path)
        dset.get_certs_from_web(
            to_download=False,
            get_active=True,
            get_archived=False,
            get_collaborative=False,
            keep_metadata=False,
            update_json=False,
        )

        assert len(list(dataset_path.iterdir())) == 0
        assert len(dset) == 3
        assert "b02ed76d2545326a" in dset.certs
        assert dset == toy_pp_dataset

        cert = dset["b02ed76d2545326a"]
        assert isinstance(cert.web_data.name, str)
        assert isinstance(cert.web_data.status, str)
        assert isinstance(cert.web_data.category, str)
        assert isinstance(cert.web_data.version, str)


@pytest.mark.remote
def test_from_web():
    dset = ProtectionProfileDataset.from_web()
    assert len(dset) > 400


@pytest.mark.remote
def test_download_html_files():
    with TemporaryDirectory() as tmp_dir:
        dset = ProtectionProfileDataset(root_dir=Path(tmp_dir))
        dset._download_html_resources(get_active=True, get_archived=False)

        for x in dset.active_html_tuples:
            assert x[1].exists()
            assert x[1].stat().st_size >= constants.MIN_PP_HTML_SIZE


@pytest.fixture(scope="module")
def downloaded_toy_dataset(tmp_path_factory):
    with as_file(files(tests.data.protection_profiles) / "dataset.json") as path:
        dataset = ProtectionProfileDataset.from_json(path)

    temp_dir = tmp_path_factory.mktemp("downloaded_dataset")
    dataset.copy_dataset(temp_dir)
    dataset.download_all_artifacts()

    for cert in dataset:
        for doc_type in ["pp", "report"]:
            link = getattr(cert.web_data, f"{doc_type}_link")
            doc_state = getattr(cert.state, doc_type)
            if link and not doc_state.download_ok:
                pytest.skip(reason="Skip due to error during download")

    return dataset


def test_downloaded_pdf_hashes(downloaded_toy_dataset: ProtectionProfileDataset):
    template_pp_pdf_hashes = {
        "c8b175590bb7fdfb": "f35ea732cfe303415080e0a95b9aa573ff9e02019e9ab971904c7530c2617b80",
        "e315e3e834a61448": "605489cda568c32371d0aeb6841df0dc63277f57113f59a5a60f8a64a1661def",
        "b02ed76d2545326a": "e88bddd8948a8624d3f350e4cb489f4b1b708e5f10e2c1402166cdfe08e5d32a",
    }
    template_report_pdf_hashes = {
        "c8b175590bb7fdfb": "c7dbaec8c333431c65129a0f429cdea22aa244e971f79139fb0ae079d4805b29",
        "e315e3e834a61448": "5f72a3ef0dce80b66c077a8a7482a1843c36e90113bd77827fba81c6e148d248",
        "b02ed76d2545326a": "e4c2d590fce870cd14fe6571a3258bd094b1e66f83f5e4d4a53a28a96f27490e",
    }

    for cert in downloaded_toy_dataset:
        assert cert.state.pp.pdf_hash == template_pp_pdf_hashes[cert.dgst]
        assert cert.state.report.pdf_hash == template_report_pdf_hashes[cert.dgst]


@pytest.mark.parametrize("converter", get_converters())
def test_convert_pdfs(
    downloaded_toy_dataset: ProtectionProfileDataset, pp_data_dir: Path, converter: type[PDFConverter]
):
    downloaded_toy_dataset.convert_all_pdfs(converter_cls=converter)

    for cert in downloaded_toy_dataset:
        assert cert.state.report.convert_ok
        assert cert.state.pp.convert_ok
        assert cert.state.report.txt_path.exists()
        assert cert.state.pp.txt_path.exists()
        if converter.HAS_JSON_OUTPUT:
            assert cert.state.report.json_path.exists()
            assert cert.state.pp.json_path.exists()

    test_crt = downloaded_toy_dataset["b02ed76d2545326a"]
    template_report_path = pp_data_dir / f"templates/{converter.get_name()}/reports/{test_crt.dgst}.txt"
    template_pp_path = pp_data_dir / f"templates/{converter.get_name()}/pps/{test_crt.dgst}.txt"

    compare_to_template(template_report_path, test_crt.state.report.txt_path)
    compare_to_template(template_pp_path, test_crt.state.pp.txt_path)


def test_keyword_extraction(toy_pp_dataset: ProtectionProfileDataset, pp_data_dir: Path, tmpdir):
    toy_pp_dataset.state.artifacts_downloaded = True
    toy_pp_dataset.state.pdfs_converted = True
    toy_pp_dataset.state.auxiliary_datasets_processed = True

    toy_pp_dataset.copy_dataset(tmpdir)

    toy_pp_dataset["b02ed76d2545326a"].state.pp.download_ok = True
    toy_pp_dataset["b02ed76d2545326a"].state.pp.convert_ok = True
    toy_pp_dataset["b02ed76d2545326a"].state.report.download_ok = True
    toy_pp_dataset["b02ed76d2545326a"].state.report.convert_ok = True

    toy_pp_dataset.analyze_certificates()
    assert toy_pp_dataset.state.certs_analyzed
    assert not toy_pp_dataset["c8b175590bb7fdfb"].state.pp.extract_ok
    assert not toy_pp_dataset["e315e3e834a61448"].state.report.extract_ok

    report_keywords = toy_pp_dataset["b02ed76d2545326a"].pdf_data.report_keywords
    assert report_keywords
    assert "cc_protection_profile_id" in report_keywords
    assert report_keywords["cc_protection_profile_id"]["BSI"]["BSI-CC-PP-0062-2010"] == 28

    pp_keywords = toy_pp_dataset["b02ed76d2545326a"].pdf_data.pp_keywords
    assert pp_keywords
    assert "cc_security_level" in pp_keywords
    assert pp_keywords["cc_security_level"]["EAL"]["EAL 2"] == 6
    assert "tee_name" in pp_keywords
    assert pp_keywords["tee_name"]["IBM"]["SE"] == 1
    assert not pp_keywords["asymmetric_crypto"]

    pp_metadata = toy_pp_dataset["b02ed76d2545326a"].pdf_data.pp_metadata
    assert pp_metadata
    assert not pp_metadata["pdf_is_encrypted"]
    assert "https://www.bsi.bund.de" in pp_metadata["pdf_hyperlinks"]

    report_metadata = toy_pp_dataset["b02ed76d2545326a"].pdf_data.report_metadata
    assert report_metadata
    assert "BSI-CC-PP-0062-2010" in report_metadata["/Title"]


def test_get_pp_by_pp_link(toy_pp_dataset: ProtectionProfileDataset):
    pp = toy_pp_dataset.get_pp_by_pp_link(
        "https://www.commoncriteriaportal.org/nfs/ccpfiles/files/ppfiles/pp0062b_pdf.pdf"
    )
    assert pp
    assert pp.dgst == "b02ed76d2545326a"
    assert not toy_pp_dataset.get_pp_by_pp_link("https://some-random-url.com")
