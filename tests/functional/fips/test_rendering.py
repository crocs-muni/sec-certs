from operator import itemgetter

import pytest
from flask.testing import FlaskClient


@pytest.mark.remote
def test_index(client: FlaskClient):
    resp = client.get("/fips/")
    assert resp.status_code == 200


@pytest.mark.remote
def test_network(client: FlaskClient):
    resp = client.get("/fips/network/graph.json")
    assert resp.status_code == 200
    resp = client.get("/fips/network/")
    assert resp.status_code == 200


@pytest.mark.remote
def test_analysis(client: FlaskClient):
    resp = client.get("/fips/analysis/")
    assert resp.status_code == 200


@pytest.mark.remote
@pytest.mark.parametrize(
    "sort", ["match", "number", "first_cert_date", "last_cert_date", "sunset_date", "level", "vendor"]
)
def test_search_basic(client: FlaskClient, sort):
    cert_id = "310"
    cert_name = "MOVEit Crypto"
    resp = client.get(f"/fips/mergedsearch/?searchType=by-name&q={cert_id}&cat=abcde&status=Any&sort={sort}")
    assert resp.status_code == 200
    assert cert_name in resp.data.decode()
    resp = client.get(f"/fips/mergedsearch/?searchType=by-name&q={cert_id}&cat=abcde&status=Active&sort={sort}")
    assert resp.status_code == 200
    assert cert_name not in resp.data.decode()


@pytest.mark.remote
def test_search_bad(client: FlaskClient):
    resp = client.get("/fips/mergedsearch/?searchType=by-name&q=aaa&page=bad")
    assert resp.status_code == 400
    resp = client.get("/fips/mergedsearch/?searchType=by-name&q=aaa&page=1&sort=bad")
    assert resp.status_code == 400
    resp = client.get("/fips/mergedsearch/?searchType=by-name&q=aaa&page=1&status=bad")
    assert resp.status_code == 400


@pytest.mark.remote
def test_fulltext_search(client: FlaskClient):
    resp = client.get("/fips/mergedsearch/?searchType=fulltext&q=hardcoded&page=1&cat=abcde&status=Active&type=target")
    assert resp.status_code == 200

    resp = client.get("/fips/mergedsearch/?searchType=fulltext&q=hardcoded&page=1&status=Any&type=target")
    assert resp.status_code == 200


@pytest.mark.remote
def test_random(client: FlaskClient):
    for _ in range(100):
        resp = client.get("/fips/random/", follow_redirects=True)
        assert resp.status_code == 200


@pytest.mark.remote
def test_entry_old(client: FlaskClient):
    resp = client.get("/fips/7d986a48cb5c4c8d3c62/")
    assert resp.location.endswith("/fips/ae1f31e1ba28b07b/")
    resp = client.get("/fips/7d986a48cb5c4c8d3c62/cert.json")
    assert resp.location.endswith("/fips/ae1f31e1ba28b07b/cert.json")
    resp = client.get("/fips/7d986a48cb5c4c8d3c62/", follow_redirects=True)
    assert resp.status_code == 200
    bad_resp = client.get("/fips/AAAAAAAAAAAAAAAAAAAA/")
    assert bad_resp.status_code == 404


@pytest.mark.remote
def test_entry(client: FlaskClient):
    hashid = "226f76b55acb4970"
    cert_id = "310"
    # cert_name = "MOVEit Crypto"
    hid_resp = client.get(f"/fips/{hashid}/", follow_redirects=True)
    assert hid_resp.status_code == 200
    cid_resp = client.get(f"/fips/id/{cert_id}", follow_redirects=True)
    assert cid_resp.status_code == 200
    assert len(cid_resp.history) == 1
    assert cid_resp.history[0].location.endswith(f"/fips/{hashid}/")
    graph_resp = client.get(f"/fips/{hashid}/graph.json")
    assert graph_resp.status_code == 200
    assert graph_resp.is_json
    cert_resp = client.get(f"/fips/{hashid}/cert.json")
    assert cert_resp.status_code == 200
    assert cert_resp.is_json
    assert client.get(f"/fips/{hashid}/target.pdf").status_code in (200, 404)
    assert client.get(f"/fips/{hashid}/target.txt").status_code in (200, 404)
    assert client.get(f"/fips/{hashid}/report.pdf").status_code in (200, 404)
    assert client.get(f"/fips/{hashid}/report.txt").status_code in (200, 404)

    bad_resp = client.get("/fips/AAAAAAAAAAAAAAAA/")
    assert bad_resp.status_code == 404
    bad_resp = client.get("/fips/AAAAAAAAAAAAAAAA/graph.json")
    assert bad_resp.status_code == 404
    bad_resp = client.get("/fips/AAAAAAAAAAAAAAAA/cert.json")
    assert bad_resp.status_code == 404
    bad_resp = client.get("/fips/id/some-bad-id-that-doesnt-exist")
    assert bad_resp.status_code == 404


@pytest.mark.remote
def test_entry_name_disambiguation(client: FlaskClient):
    name = "128 Technology Cryptographic Module"
    name_resp = client.get(f"/fips/name/{name}", follow_redirects=True)
    assert name_resp.data.count(name.encode()) == 1


@pytest.mark.remote
def test_entry_graph(client: FlaskClient):
    resp = client.get("/fips/226f76b55acb4970/graph.json")
    assert resp.is_json
    nodes = resp.json["nodes"]
    ids = set(map(itemgetter("id"), nodes))
    assert "226f76b55acb4970" in ids
    links = resp.json["links"]
    assert len(links) >= 1


@pytest.mark.remote
def test_mip(client: FlaskClient):
    resp = client.get("/fips/mip/")
    assert resp.status_code == 200
    resp = client.get("/fips/mip/dataset.json")
    assert resp.status_code == 200
    resp = client.get("/fips/mip/61f891ae309360b0d79d54ce")
    assert resp.status_code == 200
    resp = client.get("/fips/mip/61f891ae309360b0d79d54ce.json")
    assert resp.status_code == 200
    resp = client.get("/fips/mip/latest.json")
    assert resp.status_code == 200
    resp = client.get("/fips/mip/entry/BoringCrypto")
    assert resp.status_code == 200


@pytest.mark.remote
def test_iut(client: FlaskClient):
    resp = client.get("/fips/iut/")
    assert resp.status_code == 200
    resp = client.get("/fips/iut/dataset.json")
    assert resp.status_code == 200
    resp = client.get("/fips/iut/61f891ad4790725e9e9d4578")
    assert resp.status_code == 200
    resp = client.get("/fips/iut/61f891ad4790725e9e9d4578.json")
    assert resp.status_code == 200
    resp = client.get("/fips/iut/latest.json")
    assert resp.status_code == 200
    resp = client.get("/fips/iut/entry/CryptoComply")
    assert resp.status_code == 200


@pytest.mark.remote
def test_compare(client: FlaskClient):
    resp = client.get("/fips/compare/8527a891e2241369/e629fa6598d73276/")
    assert resp.status_code == 200
