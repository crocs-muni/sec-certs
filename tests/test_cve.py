from __future__ import annotations

import itertools
import json
from importlib import resources
from pathlib import Path

import pytest

import tests.data.common
from sec_certs.dataset import CVEDataset
from sec_certs.sample import CVE
from sec_certs.serialization.json import SerializationError


@pytest.fixture(scope="module")
def cve_dataset_path() -> Path:
    with resources.path(tests.data.common, "cve_dataset.json") as cve_dataset_path:
        return cve_dataset_path


@pytest.fixture(scope="module")
def cpe_match_feed() -> dict:
    with resources.open_text(tests.data.common, "cpe_match_feed.json") as handle:
        data = json.load(handle)
    return data


@pytest.fixture(scope="module")
def cve_dataset(cve_dataset_path: Path, cpe_match_feed: dict) -> CVEDataset:
    cve_dataset = CVEDataset.from_json(cve_dataset_path)
    cve_dataset.build_lookup_dict(cpe_match_feed)
    return cve_dataset


def test_cve_dset_lookup_dicts(cve_dataset: CVEDataset):
    assert cve_dataset._cpe_uri_to_cve_ids_lookup["cpe:2.3:o:linux:linux_kernel:2.4.18:*:*:*:*:*:*:*"] == {
        "CVE-2003-0001"
    }
    assert cve_dataset._cpe_uri_to_cve_ids_lookup[
        "cpe:2.3:a:ibm:security_access_manager_for_enterprise_single_sign-on:8.2.2:*:*:*:*:*:*:*"
    ] == {"CVE-2019-4513", "CVE-2017-1732"}
    assert set(itertools.chain.from_iterable(cve_dataset._cpe_uri_to_cve_ids_lookup.values())) == {
        "CVE-2019-4513",
        "CVE-2017-1732",
        "CVE-2003-0001",
    }


def test_criteria_configurations_detected(cve_dataset: CVEDataset):
    cve_ids_with_criteria_configurations = {x.cve_id for x in cve_dataset._cves_with_vulnerable_configurations}
    assert cve_ids_with_criteria_configurations == {"CVE-2003-0070", "CVE-2010-2325"}

    # In both cases single configuration with two components
    for cve_id in cve_ids_with_criteria_configurations:
        assert len(cve_dataset[cve_id].vulnerable_criteria_configurations) == 1
        assert len(cve_dataset[cve_id].vulnerable_criteria_configurations[0].components) == 2


def test_cve_dset_from_json(cve_dataset_path: Path, cve_dataset: CVEDataset, tmp_path: Path):
    dset = CVEDataset.from_json(cve_dataset_path)
    assert all(x in dset for x in cve_dataset)

    compressed_path = tmp_path / "dset.json.gz"
    cve_dataset.to_json(compressed_path, compress=True)
    decompressed_dataset = CVEDataset.from_json(compressed_path, is_compressed=True)
    assert all(x in decompressed_dataset for x in cve_dataset)


def test_cve_from_to_dict(cve_dataset: CVEDataset):
    cve = cve_dataset["CVE-2003-0070"]
    dct = cve.to_dict()
    other_cve = CVE.from_dict(dct)
    assert cve == other_cve


def test_to_pandas(cve_dataset: CVEDataset):
    df = cve_dataset.to_pandas()
    assert df.shape == (len(cve_dataset), len(CVE.pandas_columns) - 1)
    assert df.index.name == "cve_id"
    assert set(df.columns) == set(CVE.pandas_columns) - {"cve_id"}


def test_serialization_missing_path():
    dummy_dset = CVEDataset({})
    with pytest.raises(SerializationError):
        dummy_dset.to_json()
