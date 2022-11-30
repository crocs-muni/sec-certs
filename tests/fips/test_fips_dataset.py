import json
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Optional, Set

import pytest

import sec_certs.constants as constants
import tests.data.fips.dataset
from sec_certs.dataset.fips import FIPSDataset
from sec_certs.sample.fips import FIPSCertificate


@pytest.fixture(scope="module")
def data_dir() -> Path:
    return Path(tests.data.fips.dataset.__path__[0])


@pytest.fixture
def toy_dataset(data_dir: Path) -> FIPSDataset:
    return FIPSDataset.from_json(data_dir / "toy_dataset.json")


@pytest.fixture(scope="module")
def toy_static_dataset(data_dir: Path) -> FIPSDataset:
    return FIPSDataset.from_json(data_dir / "toy_dataset.json")


@pytest.fixture(scope="module")
def processed_dataset(toy_static_dataset: FIPSDataset, tmp_path_factory) -> FIPSDataset:
    tmp_dir = tmp_path_factory.mktemp("cc_dset")
    toy_static_dataset.root_dir = tmp_dir

    tested_certs = {toy_static_dataset["3095"], toy_static_dataset["3093"], toy_static_dataset["3197"]}
    toy_static_dataset.certs = {x.dgst: x for x in tested_certs}

    toy_static_dataset.download_all_artifacts()
    toy_static_dataset.convert_all_pdfs()
    toy_static_dataset._extract_data()
    toy_static_dataset._compute_references(keep_unknowns=True)
    return toy_static_dataset


@pytest.mark.parametrize(
    "input_dgst, expected_refs",
    [
        ("3095", {"3093", "3094", "3096"}),
        ("3093", {"3090", "3091"}),
        ("3197", {"3195", "3096", "3196", "3644", "3651"}),
    ],
)
def test_html_modules_directly_referencing(processed_dataset: FIPSDataset, input_dgst: str, expected_refs: Set[str]):
    crt = processed_dataset[input_dgst]
    if not crt.state.module_extract_ok:
        pytest.xfail(reason="Data from module not extracted")
    assert crt.heuristics.module_processed_references.directly_referencing == expected_refs


@pytest.mark.parametrize("input_dgst, expected_refs", [("3095", {"3093", "3094", "3096"}), ("3093", {"3090", "3091"})])
def test_pdf_policies_directly_referencing(processed_dataset: FIPSDataset, input_dgst: str, expected_refs: Set[str]):
    crt = processed_dataset[input_dgst]
    if not crt.state.policy_extract_ok:
        pytest.xfail(reason="Data from policy not extracted")
    assert crt.heuristics.policy_processed_references.directly_referencing == expected_refs


@pytest.mark.parametrize(
    "input_dgst, expected_refs",
    [
        (
            "3093",
            {
                "3090",
                "3091",
            },
        ),
        ("3095", {"3090", "3091", "3093", "3094", "3096"}),
    ],
)
def test_html_modules_indirectly_referencing(processed_dataset: FIPSDataset, input_dgst: str, expected_refs: Set[str]):
    crt = processed_dataset[input_dgst]
    if not crt.state.module_extract_ok:
        pytest.xfail(reason="Data from module not extracted")
    assert crt.heuristics.module_processed_references.indirectly_referencing == expected_refs


@pytest.mark.parametrize(
    "input_dgst, expected_refs",
    [("3095", {"3090", "3091", "3093", "3094", "3096"}), ("3093", {"3090", "3091"})],
)
def test_pdf_policies_indirectly_referencing(processed_dataset: FIPSDataset, input_dgst: str, expected_refs: Set[str]):
    crt = processed_dataset[input_dgst]
    if not crt.state.policy_extract_ok:
        pytest.xfail(reason="Data from policy not extracted")
    assert crt.heuristics.policy_processed_references.indirectly_referencing == expected_refs


@pytest.mark.parametrize("input_dgst, expected_refs", [("3095", None), ("3093", {"3095"})])
def test_html_modules_directly_referenced_by(
    processed_dataset: FIPSDataset, input_dgst: str, expected_refs: Optional[Set[str]]
):
    crt = processed_dataset[input_dgst]
    if not crt.state.module_extract_ok:
        pytest.xfail(reason="Data from module not extracted")
    assert crt.heuristics.module_processed_references.directly_referenced_by == expected_refs


@pytest.mark.parametrize("input_dgst, expected_refs", [("3095", None), ("3093", {"3095"})])
def test_pdf_policies_directly_referenced_by(
    processed_dataset: FIPSDataset, input_dgst: str, expected_refs: Optional[Set[str]]
):
    crt = processed_dataset[input_dgst]
    if not crt.state.policy_extract_ok:
        pytest.xfail(reason="Data from policy not extracted")
    assert crt.heuristics.policy_processed_references.directly_referenced_by == expected_refs


@pytest.mark.parametrize("input_dgst, expected_refs", [("3095", None), ("3093", {"3095"})])
def test_html_modules_indirectly_referenced_by(
    processed_dataset: FIPSDataset, input_dgst: str, expected_refs: Optional[Set[str]]
):
    crt = processed_dataset[input_dgst]
    if not crt.state.module_extract_ok:
        pytest.xfail(reason="Data from module not extracted")
    assert crt.heuristics.module_processed_references.indirectly_referenced_by == expected_refs


@pytest.mark.parametrize("input_dgst, expected_refs", [("3095", None), ("3093", {"3095"})])
def test_pdf_policies_indirectly_referenced_by(
    processed_dataset: FIPSDataset, input_dgst: str, expected_refs: Optional[Set[str]]
):
    crt = processed_dataset[input_dgst]
    if not crt.state.policy_extract_ok:
        pytest.xfail(reason="Data from module not extracted")
    assert crt.heuristics.module_processed_references.indirectly_referenced_by == expected_refs


def test_dataset_to_json(toy_dataset: FIPSDataset, data_dir: Path, tmp_path: Path):
    toy_dataset.to_json(tmp_path / "dset.json")

    with (tmp_path / "dset.json").open("r") as handle:
        data = json.load(handle)

    with (data_dir / "toy_dataset.json").open("r") as handle:
        template_data = json.load(handle)

    del data["timestamp"]
    del template_data["timestamp"]
    assert data == template_data


def test_dataset_from_json(toy_dataset: FIPSDataset, data_dir: Path):
    assert toy_dataset == FIPSDataset.from_json(data_dir / "toy_dataset.json")


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
        toy_dataset.root_dir = Path(tmp_dir)
        toy_dataset.download_all_artifacts()

    if not crt.state.policy_download_ok or crt.state.module_download_ok:
        pytest.xfail(reason="Fail due to error during download")

    toy_dataset.convert_all_pdfs()

    assert not crt.state.policy_convert_garbage
    assert crt.state.policy_convert_ok
    assert crt.state.policy_pdf_hash == "36b63890182f0aed29b305a0b4acc0d70b657262516f4be69138c70c2abdb1f1"
    assert crt.state.policy_txt_path.exists()

    template_policy_txt_path = data_dir / "template_policy_184097a88a9b4ad9.txt"
    assert abs(crt.state.policy_txt_path.stat().st_size - template_policy_txt_path.stat().st_size) < 1000


def test_to_pandas(toy_dataset: FIPSDataset):
    df = toy_dataset.to_pandas()
    assert df.shape == (len(toy_dataset), len(FIPSCertificate.pandas_columns))
    assert df.index.name == "dgst"
    assert set(df.columns) == set(FIPSCertificate.pandas_columns).union({"year_from"}) - {"dgst"}
