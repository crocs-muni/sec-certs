from __future__ import annotations

import os
from importlib import resources
from pathlib import Path
from typing import Any

import pytest
import yaml

import sec_certs.configuration as config_module
import tests.data.common


@pytest.fixture(autouse=True)
def load_test_config():
    with resources.path(tests.data.common, "settings_tests.yml") as path:
        config_module.config.load_from_yaml(path)


@pytest.fixture
def simple_config_dict() -> dict[str, Any]:
    return {
        "always_false_positive_fips_cert_id_threshold": 42,
        "cc_reference_annotator_should_train": False,
    }


@pytest.fixture
def simple_config_yaml(simple_config_dict, tmp_path) -> Path:
    yaml_path = tmp_path / "config.yaml"
    with yaml_path.open("w") as handle:
        yaml.safe_dump(simple_config_dict, handle)
    return yaml_path


def test_config_from_yaml(simple_config_dict, simple_config_yaml: Path) -> None:
    config_module.config.load_from_yaml(simple_config_yaml)

    for key, val in simple_config_dict.items():
        assert getattr(config_module.config, key) == val


def test_load_env_values(simple_config_dict, simple_config_yaml):
    os.environ["SECCERTS_LOG_FILEPATH"] = "/some/nonsense/path"
    os.environ["ALWAYS_FALSE_POSITIVE_FIPS_CERT_ID_THRESHOLD"] = "10"

    config_module.config.load_from_yaml(simple_config_yaml)

    # this should also beat the env set above
    for key, val in simple_config_dict.items():
        assert getattr(config_module.config, key) == val

    assert config_module.config.log_filepath == Path("/some/nonsense/path")


def test_complex_config_load(simple_config_dict, simple_config_yaml):
    config_module.config.year_difference_between_validations = 123456789
    config_module.config.n_threads = 987654321
    os.environ["SECCERTS_N_THREADS"] = "1"

    config_module.config.load_from_yaml(simple_config_yaml)
    for key, val in simple_config_dict.items():
        assert getattr(config_module.config, key) == val

    # year_difference_between_validations should not get overwritten
    assert config_module.config.year_difference_between_validations == 123456789

    # n_threads should get overwritten
    assert config_module.config.n_threads == 1
