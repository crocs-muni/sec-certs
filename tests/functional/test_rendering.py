from flask.testing import FlaskClient


def test_index(client: FlaskClient):
    resp = client.get("/")
    assert resp.status_code == 200


def test_about(client: FlaskClient):
    resp = client.get("/about/")
    assert resp.status_code == 200


def test_not_found(client: FlaskClient):
    resp = client.post("/some_path_that_does_not_exist/")
    assert resp.status_code == 404
