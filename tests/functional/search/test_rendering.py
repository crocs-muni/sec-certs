from collections import namedtuple

import pytest
from flask.testing import FlaskClient

Scheme = namedtuple("Scheme", "name prefix query cert_name")

SCHEMES = [
    Scheme(
        "cc",
        "/cc",
        "cert_id=BSI-DSZ-CC-1091-2018",
        "Veridos Suite v3.0 – cryptovision ePasslet Suite – Java Card applet configuration providing Machine-Readable Electronic Documents based on BSI TR-03110 for Official Use with BAC option",
    ),
    Scheme("fips", "/fips", "cert_id=310", "MOVEit Crypto"),
    Scheme(
        "pp",
        "/pp",
        "query=ANSSI-CC-PP-2018%2F03&search_type=name",
        "ANSSI-CC-PP-2018/03 « PC Client Specific TPM » (TPM Library specification Family “2.0”, Level 0)",
    ),
    Scheme(
        "eucc",
        "/eucc",
        "query=Secure+Smart+Grid+Hub&search_type=name",
        "Secure Smart Grid Hub (SGH-S)",
    ),
]


@pytest.mark.remote
@pytest.mark.parametrize("scheme", SCHEMES, ids=[s.name for s in SCHEMES])
def test_search_renders(client, scheme):
    resp = client.get(f"{scheme.prefix}/mergedsearch/?{scheme.query}")
    assert resp.status_code == 200
    assert scheme.cert_name in resp.data.decode()


@pytest.mark.remote
@pytest.mark.parametrize("scheme", SCHEMES, ids=[s.name for s in SCHEMES])
def test_search_ajax_partial(client, scheme):
    resp = client.get(f"{scheme.prefix}/mergedsearch/", headers={"X-Requested-With": "XMLHttpRequest"})
    assert resp.status_code == 200
    assert "search-partial" in resp.get_data(as_text=True)


@pytest.mark.remote
@pytest.mark.parametrize("scheme", SCHEMES, ids=[s.name for s in SCHEMES])
def test_search_bad(client, scheme):
    assert client.get(f"{scheme.prefix}/mergedsearch/?query=aaa&page=bad").status_code == 400
    assert client.get(f"{scheme.prefix}/mergedsearch/?query=aaa&page=1&sort_by=bad").status_code == 400
    assert client.get(f"{scheme.prefix}/mergedsearch/?query=aaa&page=1&status=bad").status_code == 400


@pytest.mark.remote
@pytest.mark.parametrize("scheme", SCHEMES, ids=[s.name for s in SCHEMES])
def test_fulltext_search(client, scheme):
    resp = client.get(f"{scheme.prefix}/mergedsearch/?query=hardcoded&search_type=fulltext&page=1")
    assert resp.status_code == 200


@pytest.mark.remote
def test_vuln_search_redirects_to_cve(client: FlaskClient):
    resp = client.get("/vuln/search/")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/vuln/cve/search/")


@pytest.mark.remote
def test_cve_search_renders(client: FlaskClient):
    resp = client.get("/vuln/cve/search/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    for cve_id in ["CVE-2019-15807", "CVE-2019-15809"]:
        assert f"/vuln/cve/{cve_id}" in body


@pytest.mark.remote
def test_cve_search_ajax_partial(client: FlaskClient):
    resp = client.get("/vuln/cve/search/", headers={"X-Requested-With": "XMLHttpRequest"})
    assert resp.status_code == 200
    assert "search-partial" in resp.get_data(as_text=True)


@pytest.mark.remote
def test_cve_search_invalid_score(client: FlaskClient):
    resp = client.get("/vuln/cve/search/", query_string={"score_from": "abc"})
    assert resp.status_code == 400


@pytest.mark.remote
def test_cpe_search_renders(client: FlaskClient):
    resp = client.get("/vuln/cpe/search/")
    assert resp.status_code == 200


@pytest.mark.remote
def test_cpe_search_ajax_partial(client: FlaskClient):
    resp = client.get("/vuln/cpe/search/", headers={"X-Requested-With": "XMLHttpRequest"})
    assert resp.status_code == 200
    assert "search-partial" in resp.get_data(as_text=True)
