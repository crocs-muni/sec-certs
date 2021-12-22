from flask.testing import FlaskClient
from urllib.parse import quote

def test_index(client: FlaskClient):
    resp = client.get("/pp/")
    assert resp.status_code == 200


def test_network(client: FlaskClient):
    resp = client.get("/pp/network/")
    assert resp.status_code == 200


def test_analysis(client: FlaskClient):
    resp = client.get("/pp/analysis/")
    assert resp.status_code == 200


# def test_search_basic(client: FlaskClient):
#     cert_id = "BSI-DSZ-CC-1091-2018"
#     cert_name = "Veridos Suite v3.0 – cryptovision ePasslet Suite – Java Card applet configuration providing Machine-Readable Electronic Documents based on BSI TR-03110 for Official Use with BAC option"
#     resp = client.get(f"/cc/search/?q={cert_id}&cat=abcdefghijklmop&status=any&sort=match")
#     assert resp.status_code == 200
#     assert cert_name in resp.data.decode()
#     resp = client.get(f"/cc/search/?q={cert_id}&cat=abcdefghijklmop&status=archived&sort=match")
#     assert resp.status_code == 200
#     assert cert_name not in resp.data.decode()


def test_random(client: FlaskClient):
    for _ in range(100):
        resp = client.get("/pp/random/", follow_redirects=True)
        assert resp.status_code == 200


def test_entry(client: FlaskClient):
    hashid = "a5ae912f6ac143a5d027"
    cert_id = "ANSSI-CC-PP-2010-04"
    hid_resp = client.get(f"/pp/{hashid}/", follow_redirects=True)
    assert hid_resp.status_code == 200
    cid_resp = client.get(f"/pp/id/{cert_id}", follow_redirects=True)
    assert cid_resp.status_code == 200
    assert len(cid_resp.history) == 1
    assert cid_resp.history[0].location.endswith(f"/pp/{hashid}/")
    profile_resp = client.get(f"/pp/{hashid}/profile.json")
    assert profile_resp.status_code == 200
    assert profile_resp.is_json
