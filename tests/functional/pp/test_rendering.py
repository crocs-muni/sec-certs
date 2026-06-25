import pytest
from flask.testing import FlaskClient


@pytest.mark.remote
def test_index(client: FlaskClient):
    resp = client.get("/pp/")
    assert resp.status_code == 200


@pytest.mark.remote
def test_network(client: FlaskClient):
    resp = client.get("/pp/network/")
    assert resp.status_code == 200


@pytest.mark.remote
def test_analysis(client: FlaskClient):
    resp = client.get("/pp/analysis/")
    assert resp.status_code == 200


@pytest.mark.remote
def test_random(client: FlaskClient):
    for _ in range(100):
        resp = client.get("/pp/random/", follow_redirects=True)
        assert resp.status_code == 200


@pytest.mark.remote
def test_entry(client: FlaskClient):
    hashid = "7b81fd67c02d34de"
    # cert_id = "ANSSI-CC-PP-2010-04"
    hid_resp = client.get(f"/pp/{hashid}/", follow_redirects=True)
    assert hid_resp.status_code == 200
    # cid_resp = client.get(f"/pp/id/{cert_id}", follow_redirects=True)
    # assert cid_resp.status_code == 200
    # assert len(cid_resp.history) == 1
    # assert cid_resp.history[0].location.endswith(f"/pp/{hashid}/")
    profile_resp = client.get(f"/pp/{hashid}/profile.json")
    assert profile_resp.status_code == 200
    assert profile_resp.is_json


@pytest.mark.remote
def test_entry_name_disambiguation(client: FlaskClient):
    name = "Card Operating System Generation 2"
    name_resp = client.get(f"/pp/name/{name}", follow_redirects=True)
    assert name_resp.data.count(name.encode()) == 4
