from flask.testing import FlaskClient


def test_index(client: FlaskClient):
    resp = client.get("/cc/")
    assert resp.status_code == 200


def test_random(client: FlaskClient):
    for _ in range(100):
        resp = client.get("/cc/random/", follow_redirects=True)
        assert resp.status_code == 200
