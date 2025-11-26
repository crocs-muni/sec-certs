from datetime import date, datetime
from importlib.resources import files
from typing import Any

import pytest

from sec_certs.configuration import config
from sec_certs.dataset import CPEDataset, CVEDataset
from sec_certs.utils.nvd_dataset_builder import (
    CpeMatchNvdDatasetBuilder,
    CpeNvdDatasetBuilder,
    CveNvdDatasetBuilder,
    NvdDatasetBuilder,
)


@pytest.fixture(autouse=True)
def load_test_config():
    with files("tests.data.common") / "settings_tests.yml" as path:
        config.load_from_yaml(path)


@pytest.mark.remote
@pytest.mark.parametrize(
    "default_dataset, builder_class",
    [
        (CPEDataset(), CpeNvdDatasetBuilder),
        (CVEDataset(), CveNvdDatasetBuilder),
        ({"timestamp": datetime.fromtimestamp(0).isoformat(), "match_strings": {}}, CpeMatchNvdDatasetBuilder),
    ],
)
def test_build_dataset(default_dataset: Any, builder_class: type[NvdDatasetBuilder]):
    def get_update_timestamp_from_dataset(dset) -> datetime:
        if isinstance(dset, CPEDataset | CVEDataset):
            return dset.last_update_timestamp
        return datetime.fromisoformat(dset["timestamp"])

    def get_dataset_len(dset) -> int:
        if isinstance(dset, CPEDataset | CVEDataset):
            return len(dset)
        return len(dset["match_strings"])

    config.preferred_source_remote_datasets = "origin"
    with builder_class(api_key=config.nvd_api_key) as dataset_builder:
        dataset = dataset_builder._init_new_dataset()
        assert dataset == default_dataset
        last_update = dataset_builder._get_last_update_from_previous_data(dataset)
        dataset_builder._fill_in_mod_dates(False, last_update)
        dataset_builder._build_arguments()

        assert len(dataset_builder._requests_to_process) > 90
        assert not dataset_builder._ok_responses
        assert dataset_builder._attempts_left == dataset_builder.max_attempts

        dataset_builder._requests_to_process = dataset_builder._requests_to_process[-1:]
        dataset_builder._request_parallel_and_handle_responses()
        assert not dataset_builder._requests_to_process
        assert len(dataset_builder._ok_responses) == 1

        dataset = dataset_builder._process_responses(dataset_builder._ok_responses, dataset)

        assert get_update_timestamp_from_dataset(dataset).date() == date.today()
        assert (
            get_dataset_len(dataset) > 200
        )  # some items may be irrelevant, it's hard to tell how many, this is Bulgarian constant.
