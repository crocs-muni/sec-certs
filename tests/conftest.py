from pathlib import Path

import pytest

import tests.data
from sec_certs.configuration import config


@pytest.fixture(scope="module", autouse=True)
def load_test_config():
    pth = Path(tests.data.__path__[0]) / "settings_tests.yml"
    config.load_from_yaml(pth)
