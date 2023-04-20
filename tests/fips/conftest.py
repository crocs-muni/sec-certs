from importlib import resources

import pytest
import tests.data.fips.dataset

from sec_certs.dataset import FIPSDataset


@pytest.fixture(scope="module")
def toy_dataset() -> FIPSDataset:
    with resources.path(tests.data.fips.dataset, "toy_dataset.json") as dataset_path:
        return FIPSDataset.from_json(dataset_path)
