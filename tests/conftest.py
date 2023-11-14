import json
from collections.abc import Generator
from importlib import resources
from pathlib import Path

import pytest

import tests.data.common
from sec_certs.configuration import config
from sec_certs.dataset import CPEDataset, CVEDataset


@pytest.fixture(scope="module", autouse=True)
def load_test_config():
    with resources.path(tests.data.common, "settings_tests.yml") as path:
        config.load_from_yaml(path)


@pytest.fixture(scope="module")
def cve_dataset_path() -> Generator[Path, None, None]:
    with resources.path(tests.data.common, "cve_dataset.json") as cve_dataset_path:
        yield cve_dataset_path


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


@pytest.fixture(scope="module")
def cpe_dataset_path() -> Generator[Path, None, None]:
    with resources.path(tests.data.common, "cpe_dataset.json") as cpe_dataset_path:
        yield cpe_dataset_path


@pytest.fixture(scope="module")
def cpe_dataset(cpe_dataset_path: Path) -> CPEDataset:
    return CPEDataset.from_json(cpe_dataset_path)
