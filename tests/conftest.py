import os

import pytest

from sec_certs_page import app
from tests.functional.client import RemoteTestClient


@pytest.fixture(scope="function")
def client():
    if os.getenv("TEST_REMOTE"):
        yield RemoteTestClient("https://seccerts.org")
    else:
        with app.test_client() as testing_client:
            with app.app_context():
                yield testing_client
