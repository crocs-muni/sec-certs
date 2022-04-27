import pytest
from flask.testing import FlaskClient


@pytest.mark.remote
def test_index(client: FlaskClient):
    resp = client.get("/")
    assert resp.status_code == 200


@pytest.mark.remote
def test_about(client: FlaskClient):
    resp = client.get("/about/")
    assert resp.status_code == 200


@pytest.mark.remote
def test_not_found(client: FlaskClient):
    resp = client.get("/some_path_that_does_not_exist/")
    assert resp.status_code == 404


@pytest.mark.remote
def test_sitemaps(client: FlaskClient):
    resp = client.get("/sitemap.xml")
    assert resp.status_code == 200
