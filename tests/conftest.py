from pathlib import Path

import pytest

import tests.data
from sec_certs.config.configuration import config


@pytest.fixture(scope="session", autouse=True)
def load_test_config():
    pth = Path(tests.data.__path__[0]) / "settings_tests.yml"
    config.load(pth)
