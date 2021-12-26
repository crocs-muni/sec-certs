import pytest
from flask.testing import FlaskClient


def test_index(client: FlaskClient):
    resp = client.get("/cc/")
    assert resp.status_code == 200


def test_network(client: FlaskClient):
    resp = client.get("/cc/network/")
    assert resp.status_code == 200
    resp = client.get("/cc/network/graph.json")
    assert resp.status_code == 200


def test_analysis(client: FlaskClient):
    resp = client.get("/cc/analysis/")
    assert resp.status_code == 200


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_search_basic(client: FlaskClient):
    cert_id = "BSI-DSZ-CC-1091-2018"
    cert_name = "Veridos Suite v3.0 – cryptovision ePasslet Suite – Java Card applet configuration providing Machine-Readable Electronic Documents based on BSI TR-03110 for Official Use with BAC option"
    resp = client.get(f"/cc/search/?q={cert_id}&cat=abcdefghijklmop&status=any&sort=match")
    assert resp.status_code == 200
    assert cert_name in resp.data.decode()
    resp = client.get(f"/cc/search/?q={cert_id}&cat=abcdefghijklmop&status=archived&sort=match")
    assert resp.status_code == 200
    assert cert_name not in resp.data.decode()


def test_random(client: FlaskClient):
    for _ in range(100):
        resp = client.get("/cc/random/", follow_redirects=True)
        assert resp.status_code == 200


def test_old_entry(client: FlaskClient):
    resp = client.get("/cc/bf712f246f61e8678855/")
    assert resp.location.endswith("/cc/4a1fa75170579066/")
    resp = client.get("/cc/bf712f246f61e8678855/", follow_redirects=True)
    assert resp.status_code == 200


def test_entry(client: FlaskClient):
    hashid = "3da6e0f0f97b3d2f"
    cert_id = "BSI-DSZ-CC-1091-2018"
    cert_name = "Veridos Suite v3.0 – cryptovision ePasslet Suite – Java Card applet configuration providing Machine-Readable Electronic Documents based on BSI TR-03110 for Official Use with BAC option"
    hid_resp = client.get(f"/cc/{hashid}/", follow_redirects=True)
    assert hid_resp.status_code == 200
    cid_resp = client.get(f"/cc/id/{cert_id}", follow_redirects=True)
    assert cid_resp.status_code == 200
    assert len(cid_resp.history) == 1
    assert cid_resp.history[0].location.endswith(f"/cc/{hashid}/")
    name_resp = client.get(f"/cc/name/{cert_name}", follow_redirects=True)
    assert name_resp.status_code == 200
    assert len(name_resp.history) == 1
    assert name_resp.history[0].location.endswith(f"/cc/{hashid}/")
    graph_resp = client.get(f"/cc/{hashid}/graph.json")
    assert graph_resp.status_code == 200
    assert graph_resp.is_json
    cert_resp = client.get(f"/cc/{hashid}/cert.json")
    assert cert_resp.status_code == 200
    assert cert_resp.is_json
