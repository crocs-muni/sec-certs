from flask.testing import FlaskClient

# Severity bitmask bit positions follow sec_certs_page.vuln.search.CVE_SEVERITIES:
# ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].
SEVERITY_MEDIUM = format(1 << 2, "x")  # only MEDIUM
SEVERITY_CRITICAL = format(1 << 0, "x")  # only CRITICAL

# Both CVEs in the test dataset are MEDIUM severity.
CVE_IDS = ["CVE-2019-15807", "CVE-2019-15809"]


def _cve_link(cve_id):
    # The detail link only appears in actual result rows (not in placeholders etc.).
    return f"/vuln/cve/{cve_id}"


def test_search_redirects_to_cve(client: FlaskClient):
    resp = client.get("/vuln/search/")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/vuln/cve/search/")


def test_cve_search_page(client: FlaskClient):
    resp = client.get("/vuln/cve/search/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    for cve_id in CVE_IDS:
        assert _cve_link(cve_id) in body


def test_cve_search_by_id(client: FlaskClient):
    resp = client.get("/vuln/cve/search/", query_string={"query": "CVE-2019-15809"})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert _cve_link("CVE-2019-15809") in body


def test_cve_search_severity_filter(client: FlaskClient):
    # Only MEDIUM selected -> both test CVEs match.
    resp = client.get("/vuln/cve/search/", query_string={"severities": SEVERITY_MEDIUM})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert all(_cve_link(cve_id) in body for cve_id in CVE_IDS)

    # Only CRITICAL selected -> no test CVE matches.
    resp = client.get("/vuln/cve/search/", query_string={"severities": SEVERITY_CRITICAL})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert not any(_cve_link(cve_id) in body for cve_id in CVE_IDS)
    assert "No results found" in body


def test_cve_search_score_range(client: FlaskClient):
    # Both CVEs have base_score 4.7.
    resp = client.get("/vuln/cve/search/", query_string={"score_from": "4", "score_to": "5"})
    assert resp.status_code == 200
    assert all(_cve_link(cve_id) in resp.get_data(as_text=True) for cve_id in CVE_IDS)

    resp = client.get("/vuln/cve/search/", query_string={"score_from": "8"})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert not any(_cve_link(cve_id) in body for cve_id in CVE_IDS)
    assert "No results found" in body


def test_cve_search_sort_by_cert_count(client: FlaskClient):
    resp = client.get("/vuln/cve/search/", query_string={"sort_by": "cert_count", "sort_dir": "desc"})
    assert resp.status_code == 200


def test_cve_search_ajax_partial(client: FlaskClient):
    resp = client.get("/vuln/cve/search/", headers={"X-Requested-With": "XMLHttpRequest"})
    assert resp.status_code == 200
    assert "search-partial" in resp.get_data(as_text=True)


def test_cve_search_invalid_score(client: FlaskClient):
    resp = client.get("/vuln/cve/search/", query_string={"score_from": "abc"})
    assert resp.status_code == 400


def test_cpe_search_page(client: FlaskClient):
    resp = client.get("/vuln/cpe/search/")
    assert resp.status_code == 200


def test_cpe_search_by_query(client: FlaskClient):
    resp = client.get("/vuln/cpe/search/", query_string={"query": "tecsec"})
    assert resp.status_code == 200
    assert "armored" in resp.get_data(as_text=True)


def test_cpe_search_vendor_filter(client: FlaskClient):
    resp = client.get("/vuln/cpe/search/", query_string={"vendor": "tecsec"})
    assert resp.status_code == 200
    assert "tecsec" in resp.get_data(as_text=True)


def test_cpe_search_ajax_partial(client: FlaskClient):
    resp = client.get("/vuln/cpe/search/", headers={"X-Requested-With": "XMLHttpRequest"})
    assert resp.status_code == 200
    assert "search-partial" in resp.get_data(as_text=True)
