import os

import pytest
from flask import Flask

from sec_certs_page import app as sec_certs_app
from tests.functional.client import RemoteTestClient


@pytest.fixture(scope="session")
def app():
    with sec_certs_app.app_context():
        yield sec_certs_app


@pytest.fixture(scope="function")
def client(app: Flask):
    if os.getenv("TEST_REMOTE"):
        yield RemoteTestClient("https://seccerts.org")
    else:
        with app.test_client() as testing_client:
            yield testing_client
