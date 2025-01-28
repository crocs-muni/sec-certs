from unittest.mock import mock_open

import pytest

from sec_certs.configuration import config
from sec_certs.dataset import (
    CCDatasetMaintenanceUpdates,
    CCSchemeDataset,
    CPEDataset,
    CVEDataset,
    FIPSAlgorithmDataset,
    ProtectionProfileDataset,
)
from sec_certs.dataset.auxiliary_dataset_handling import (
    CCMaintenanceUpdateDatasetHandler,
    CCSchemeDatasetHandler,
    CPEDatasetHandler,
    CPEMatchDictHandler,
    CVEDatasetHandler,
    FIPSAlgorithmDatasetHandler,
    ProtectionProfileDatasetHandler,
)


@pytest.fixture
def temp_dir(tmp_path):
    return tmp_path


@pytest.fixture
def mock_dset():
    return {"key": "value"}


def test_cpe_dataset_handler_set_local_paths(temp_dir):
    handler = CPEDatasetHandler(temp_dir)
    new_path = temp_dir / "new_path"
    handler.set_local_paths(new_path)
    assert handler.aux_datasets_dir == new_path


@pytest.mark.parametrize("preferred_source_aux_datasets", ["sec-certs", "api"])
def test_cpe_dataset_handler_process_dataset(preferred_source_aux_datasets, temp_dir, monkeypatch):
    config.preferred_source_aux_datasets = preferred_source_aux_datasets
    handler = CPEDatasetHandler(temp_dir)
    mock_dset = CPEDataset()

    def mock_get_dset(path):
        return mock_dset

    if preferred_source_aux_datasets == "sec-certs":
        monkeypatch.setattr("sec_certs.dataset.cpe.CPEDataset.from_web", mock_get_dset)
    else:
        monkeypatch.setattr("sec_certs.utils.nvd_dataset_builder.CpeNvdDatasetBuilder.build_dataset", mock_get_dset)

    monkeypatch.setattr("sec_certs.dataset.cpe.CPEDataset.to_json", lambda x: None)
    handler.process_dataset(download_fresh=True)

    assert handler.dset == mock_dset
    assert handler.dset_path == temp_dir / "cpe_dataset.json"


def test_cve_dataset_handler_set_local_paths(temp_dir):
    handler = CVEDatasetHandler(temp_dir)
    new_path = temp_dir / "new_path"
    handler.set_local_paths(new_path)
    assert handler.aux_datasets_dir == new_path


@pytest.mark.parametrize("preferred_source_aux_datasets", ["sec-certs", "api"])
def test_cve_dataset_handler_process_dataset(preferred_source_aux_datasets, temp_dir, monkeypatch):
    config.preferred_source_aux_datasets = preferred_source_aux_datasets
    handler = CVEDatasetHandler(temp_dir)
    mock_dset = CVEDataset()

    def mock_get_dset(path):
        return mock_dset

    if preferred_source_aux_datasets == "sec-certs":
        monkeypatch.setattr("sec_certs.dataset.cve.CVEDataset.from_web", mock_get_dset)
    else:
        monkeypatch.setattr("sec_certs.utils.nvd_dataset_builder.CveNvdDatasetBuilder.build_dataset", mock_get_dset)
    monkeypatch.setattr("sec_certs.dataset.cve.CVEDataset.to_json", lambda x: None)
    handler.process_dataset(download_fresh=True)

    assert handler.dset == mock_dset
    assert handler.dset_path == temp_dir / "cve_dataset.json"


def test_cpe_match_dict_handler_set_local_paths(temp_dir):
    handler = CPEMatchDictHandler(temp_dir)
    new_path = temp_dir / "new_path"
    handler.set_local_paths(new_path)
    assert handler.aux_datasets_dir == new_path


@pytest.mark.parametrize("preferred_source_aux_datasets", ["sec-certs", "api"])
def test_cpe_match_dict_handler_process_dataset(preferred_source_aux_datasets, temp_dir, monkeypatch):
    config.preferred_source_aux_datasets = preferred_source_aux_datasets
    handler = CPEMatchDictHandler(temp_dir)
    mock_dset = {"key": "value"}
    mock_dset_str_single_quotes = '{"key": "value"}'

    def mock_get_dset(path):
        return mock_dset

    def mock_download_file(url, path, progress_bar_desc):
        return 200

    if preferred_source_aux_datasets == "api":
        monkeypatch.setattr(
            "sec_certs.utils.nvd_dataset_builder.CpeMatchNvdDatasetBuilder.build_dataset", mock_get_dset
        )
    else:
        monkeypatch.setattr("sec_certs.utils.helpers.download_file", mock_download_file)
        monkeypatch.setattr("gzip.open", mock_open(read_data=(mock_dset_str_single_quotes.encode())))

    handler.process_dataset(download_fresh=True)

    assert handler.dset == mock_dset


def test_fips_algorithm_dataset_handler_set_local_paths(temp_dir):
    handler = FIPSAlgorithmDatasetHandler(temp_dir)
    new_path = temp_dir / "new_path"
    handler.set_local_paths(new_path)
    assert handler.aux_datasets_dir == new_path


def test_fips_algorithm_dataset_handler_process_dataset(temp_dir, monkeypatch):
    handler = FIPSAlgorithmDatasetHandler(temp_dir)
    mock_dset = FIPSAlgorithmDataset()

    def mock_from_web(path):
        return mock_dset

    monkeypatch.setattr("sec_certs.dataset.fips_algorithm.FIPSAlgorithmDataset.from_web", mock_from_web)
    monkeypatch.setattr("sec_certs.dataset.fips_algorithm.FIPSAlgorithmDataset.to_json", lambda x: None)
    handler.process_dataset(download_fresh=True)
    assert handler.dset == mock_dset
    assert handler.dset_path == temp_dir / "algorithms.json"
    assert handler.dset.json_path == handler.dset_path


def test_cc_scheme_dataset_handler_set_local_paths(temp_dir):
    handler = CCSchemeDatasetHandler(temp_dir)
    new_path = temp_dir / "new_path"
    handler.set_local_paths(new_path)
    assert handler.aux_datasets_dir == new_path


def test_cc_scheme_dataset_handler_process_dataset(temp_dir, monkeypatch):
    handler = CCSchemeDatasetHandler(temp_dir)
    mock_dset = CCSchemeDataset(schemes={})

    def mock_from_web(path, only_schemes):
        return mock_dset

    monkeypatch.setattr("sec_certs.dataset.cc_scheme.CCSchemeDataset.from_web", mock_from_web)
    monkeypatch.setattr("sec_certs.dataset.cc_scheme.CCSchemeDataset.to_json", lambda x: None)
    handler.process_dataset(download_fresh=True)
    assert handler.dset == mock_dset
    assert handler.dset_path == temp_dir / "cc_scheme.json"
    assert handler.dset.json_path == handler.dset_path


def test_cc_maintenance_update_dataset_handler_set_local_paths(temp_dir):
    handler = CCMaintenanceUpdateDatasetHandler(temp_dir)
    new_path = temp_dir / "new_path"
    handler.set_local_paths(new_path)
    assert handler.aux_datasets_dir == new_path


def test_cc_maintenance_update_dataset_handler_process_dataset(temp_dir, monkeypatch):
    handler = CCMaintenanceUpdateDatasetHandler(temp_dir)
    mock_dset = CCDatasetMaintenanceUpdates(root_dir=handler.dset_path.parent, name="maintenance_updates")

    monkeypatch.setattr(
        "sec_certs.sample.cc_maintenance_update.CCMaintenanceUpdate.get_updates_from_cc_cert",
        lambda x: [],
    )
    monkeypatch.setattr("sec_certs.dataset.dataset.Dataset.download_all_artifacts", lambda x: None)
    monkeypatch.setattr("sec_certs.dataset.dataset.Dataset.convert_all_pdfs", lambda x: None)
    monkeypatch.setattr("sec_certs.dataset.cc.CCDataset.extract_data", lambda x: None)
    monkeypatch.setattr("sec_certs.dataset.dataset.Dataset.to_json", lambda x: None)
    handler.process_dataset(download_fresh=True)
    assert handler.dset == mock_dset


def test_protection_profile_dataset_handler_set_local_paths(temp_dir):
    handler = ProtectionProfileDatasetHandler(temp_dir)
    new_path = temp_dir / "new_path"
    handler.set_local_paths(new_path)
    assert handler.aux_datasets_dir == new_path


def test_protection_profile_dataset_handler_process_dataset(temp_dir, monkeypatch):
    handler = ProtectionProfileDatasetHandler(temp_dir)
    mock_dset = ProtectionProfileDataset()

    monkeypatch.setattr(
        "sec_certs.dataset.protection_profile.ProtectionProfileDataset.get_certs_from_web", lambda x: None
    )
    monkeypatch.setattr(
        "sec_certs.dataset.protection_profile.ProtectionProfileDataset.download_all_artifacts", lambda x: None
    )
    monkeypatch.setattr(
        "sec_certs.dataset.protection_profile.ProtectionProfileDataset.convert_all_pdfs", lambda x: None
    )
    monkeypatch.setattr(
        "sec_certs.dataset.protection_profile.ProtectionProfileDataset.analyze_certificates", lambda x: None
    )
    monkeypatch.setattr("sec_certs.dataset.protection_profile.ProtectionProfileDataset.to_json", lambda x: None)
    handler.process_dataset(download_fresh=True)
    assert handler.dset == mock_dset
