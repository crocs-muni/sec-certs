import pytest
from sec_certs_page import app


@pytest.fixture(scope="function")
def client():
    with app.test_client() as testing_client:
        with app.app_context():
            yield testing_client
