import pytest
from flask.testing import FlaskClient


@pytest.mark.remote
def test_index(client: FlaskClient):
    resp = client.get("/cc/")
    assert resp.status_code == 200


@pytest.mark.remote
def test_network(client: FlaskClient):
    resp = client.get("/cc/network/")
    assert resp.status_code == 200
    resp = client.get("/cc/network/graph.json")
    assert resp.status_code == 200


@pytest.mark.remote
def test_analysis(client: FlaskClient):
    resp = client.get("/cc/analysis/")
    assert resp.status_code == 200


@pytest.mark.remote
def test_search_basic(client: FlaskClient):
    cert_id = "BSI-DSZ-CC-1091-2018"
    cert_name = "Veridos Suite v3.0 – cryptovision ePasslet Suite – Java Card applet configuration providing Machine-Readable Electronic Documents based on BSI TR-03110 for Official Use with BAC option"
    resp = client.get(f"/cc/search/?q={cert_id}&cat=abcdefghijklmop&status=any&sort=match")
    assert resp.status_code == 200
    assert cert_name in resp.data.decode()
    resp = client.get(f"/cc/search/?q={cert_id}&cat=abcdefghijklmop&status=active&sort=match")
    assert resp.status_code == 200
    assert cert_name not in resp.data.decode()


@pytest.mark.remote
def test_search_pagination(client: FlaskClient):
    cert_id = "BSI-DSZ-CC-1091-2018"
    cert_name = "Veridos Suite v3.0 – cryptovision ePasslet Suite – Java Card applet configuration providing Machine-Readable Electronic Documents based on BSI TR-03110 for Official Use with BAC option"
    resp = client.get(f"/cc/search/results/?q={cert_id}&cat=abcdefghijklmop&status=any&sort=match")
    assert resp.status_code == 200
    assert cert_name in resp.data.decode()
    resp = client.get(f"/cc/search/results/?q={cert_id}&cat=abcdefghijklmop&status=active&sort=match")
    assert resp.status_code == 200
    assert cert_name not in resp.data.decode()


@pytest.mark.remote
def test_search_bad(client: FlaskClient):
    resp = client.get("/cc/search/?q=aaa&page=bad")
    assert resp.status_code == 400
    resp = client.get("/cc/search/?q=aaa&page=1&sort=bad")
    assert resp.status_code == 400
    resp = client.get("/cc/search/?q=aaa&page=1&status=bad")
    assert resp.status_code == 400


@pytest.mark.remote
def test_fulltext_search(client: FlaskClient):
    resp = client.get("/cc/ftsearch/?q=hardcoded&page=1&cat=abcdefghijklmop&status=any&type=report")
    assert resp.status_code == 200

    resp = client.get("/cc/ftsearch/?q=hardcoded&page=1&status=active&type=report")
    assert resp.status_code == 200


@pytest.mark.remote
def test_random(client: FlaskClient):
    for _ in range(100):
        resp = client.get("/cc/random/", follow_redirects=True)
        assert resp.status_code == 200


@pytest.mark.remote
def test_old_entry(client: FlaskClient):
    resp = client.get("/cc/bf712f246f61e8678855/")
    assert resp.location.endswith("/cc/4a1fa75170579066/")
    resp = client.get("/cc/bf712f246f61e8678855/cert.json")
    assert resp.location.endswith("/cc/4a1fa75170579066/cert.json")
    resp = client.get("/cc/bf712f246f61e8678855/", follow_redirects=True)
    assert resp.status_code == 200
    bad_resp = client.get("/cc/AAAAAAAAAAAAAAAAAAAA/")
    assert bad_resp.status_code == 404


@pytest.mark.remote
def test_entry(client: FlaskClient):
    hashid = "3d1b01ce576f605d"
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
    assert client.get(f"/cc/{hashid}/target.pdf").status_code in (200, 404)
    assert client.get(f"/cc/{hashid}/target.txt").status_code in (200, 404)
    assert client.get(f"/cc/{hashid}/report.pdf").status_code in (200, 404)
    assert client.get(f"/cc/{hashid}/report.txt").status_code in (200, 404)
    bad_resp = client.get("/cc/AAAAAAAAAAAAAAAA/")
    assert bad_resp.status_code == 404


@pytest.mark.remote
def test_entry_name_disambiguation(client: FlaskClient):
    name = "AhnLab MDS, MDS with MTA, and MDS Manager v2.1"
    name_resp = client.get(f"/cc/name/{name}", follow_redirects=True)
    assert name_resp.data.count(name.encode()) == 3


@pytest.mark.remote
def test_entry_graph(client: FlaskClient):
    resp = client.get("/cc/663b9c1bde7447b3/graph.json")
    assert resp.is_json
    nodes = resp.json["nodes"]
    assert len(nodes) == 1
    assert nodes[0]["id"] == "663b9c1bde7447b3"
    links = resp.json["links"]
    assert len(links) == 0


@pytest.mark.remote
def test_compare(client: FlaskClient):
    resp = client.get("/cc/compare/dba20653348d0d12/eeff5b346faba43f/")
    assert resp.status_code == 200
