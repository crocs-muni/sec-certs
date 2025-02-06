from urllib.parse import quote

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
def test_search_basic(client: FlaskClient):
    pp_id = quote("ANSSI-CC-PP-2018/03", safe="")
    pp_name = "ANSSI-CC-PP-2018/03 « PC Client Specific TPM » (TPM Library specification Family “2.0”, Level 0)"
    resp = client.get(f"/pp/search/?q={pp_id}&cat=abcdefghijklmop&status=any&sort=match")
    assert resp.status_code == 200
    assert pp_name in resp.data.decode()
    resp = client.get(f"/pp/search/?q={pp_id}&cat=abcdefghijklmop&status=archived&sort=match")
    assert resp.status_code == 200
    assert pp_name not in resp.data.decode()


@pytest.mark.remote
def test_search_pagination(client: FlaskClient):
    pp_id = quote("ANSSI-CC-PP-2018/03", safe="")
    pp_name = "ANSSI-CC-PP-2018/03 « PC Client Specific TPM » (TPM Library specification Family “2.0”, Level 0)"
    resp = client.get(f"/pp/search/pagination/?q={pp_id}&cat=abcdefghijklmop&status=any&sort=match")
    assert resp.status_code == 200
    assert pp_name in resp.data.decode()
    resp = client.get(f"/pp/search/pagination/?q={pp_id}&cat=abcdefghijklmop&status=archived&sort=match")
    assert resp.status_code == 200
    assert pp_name not in resp.data.decode()


@pytest.mark.remote
def test_search_bad(client: FlaskClient):
    resp = client.get("/pp/search/?q=aaa&page=bad")
    assert resp.status_code == 400
    resp = client.get("/pp/search/?q=aaa&page=1&sort=bad")
    assert resp.status_code == 400
    resp = client.get("/pp/search/?q=aaa&page=1&status=bad")
    assert resp.status_code == 400


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
