from flask.testing import FlaskClient


def test_index(client: FlaskClient):
    resp = client.get("/fips/")
    assert resp.status_code == 200


def test_random(client: FlaskClient):
    for _ in range(100):
        resp = client.get("/fips/random/", follow_redirects=True)
        assert resp.status_code == 200
