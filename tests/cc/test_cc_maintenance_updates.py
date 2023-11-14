import json
from collections.abc import Generator
from importlib import resources
from pathlib import Path

import pytest
import tests.data.cc.dataset

from sec_certs.dataset import CCDatasetMaintenanceUpdates
from sec_certs.sample.cc_maintenance_update import CCMaintenanceUpdate


@pytest.fixture(scope="module")
def data_dir() -> Generator[Path, None, None]:
    with resources.path(tests.data.cc.dataset, "") as path:
        yield path


@pytest.fixture
def mu_dset(data_dir: Path, tmp_path_factory) -> CCDatasetMaintenanceUpdates:
    tmp_dir = tmp_path_factory.mktemp("mu_dset")
    dset = CCDatasetMaintenanceUpdates.from_json(data_dir / "auxiliary_datasets/maintenances/maintenance_updates.json")
    dset.copy_dataset(tmp_dir)
    return dset


def test_methods_not_meant_to_be_implemented():
    dset = CCDatasetMaintenanceUpdates()
    with pytest.raises(NotImplementedError):
        dset.analyze_certificates()
    with pytest.raises(NotImplementedError):
        dset._compute_heuristics()
    with pytest.raises(NotImplementedError):
        dset.process_auxiliary_datasets()
    with pytest.raises(NotImplementedError):
        dset.compute_related_cves()
    with pytest.raises(NotImplementedError):
        dset.get_certs_from_web()


def test_download_artifacts(mu_dset: CCDatasetMaintenanceUpdates):
    # Conversion and extraction is identical to CC, will not test.
    mu_dset.download_all_artifacts()
    mu = mu_dset["cert_8a5e6bcda602920c_update_559ed93dd80320b5"]

    if not (mu.state.report_download_ok or mu.state.st_download_ok):
        pytest.xfail(reason="Fail due to error on CC server.")

    assert mu.state.report_pdf_hash == "80bada65614c1b037c13efa78996a8910700d0e05a3ca217286f76d7dacefe62"
    assert mu.state.st_pdf_hash == "d42e4364d037ba742fcd4050a9a84d0e6300f93eb68bcfe8c61f72c429c9ceca"


def test_dataset_to_json(mu_dset: CCDatasetMaintenanceUpdates, data_dir: Path, tmp_path: Path):
    mu_dset.to_json(tmp_path / "dset.json")

    with (tmp_path / "dset.json").open("r") as handle:
        data = json.load(handle)

    with (data_dir / "auxiliary_datasets/maintenances/maintenance_updates.json").open("r") as handle:
        template_data = json.load(handle)

    del template_data["timestamp"]
    del data["timestamp"]
    assert data == template_data


def test_dataset_from_json(mu_dset: CCDatasetMaintenanceUpdates, data_dir: Path):
    assert mu_dset == CCDatasetMaintenanceUpdates.from_json(
        data_dir / "auxiliary_datasets/maintenances/maintenance_updates.json"
    )


def test_to_pandas(mu_dset: CCDatasetMaintenanceUpdates):
    df = mu_dset.to_pandas()
    assert df.shape == (len(mu_dset), len(CCMaintenanceUpdate.pandas_columns) - 1)
    assert df.index.name == "dgst"
    assert set(df.columns) == set(CCMaintenanceUpdate.pandas_columns) - {"dgst"}


@pytest.mark.skip(reason="Will work only with fresh snapshot on seccerts.org")
def test_from_web():
    dset = CCDatasetMaintenanceUpdates.from_web_latest()
    assert dset is not None
    assert len(dset) >= 492  # Contents as of November 2022, maintenances should not disappear
    assert "cert_8a5e6bcda602920c_update_559ed93dd80320b5" in dset  # random cert verified to be present
