import re
from http import HTTPStatus

import pytest
from flask.testing import FlaskClient
from sec_certs_page import mongo


def _extract_row(body: str, cs_name: str) -> str:
    match = re.search(rf'<tr data-cs-name="{re.escape(cs_name)}">.*?</tr>', body, re.DOTALL)
    assert match, f'No row found for data-cs-name="{cs_name}"'
    return match.group(0)


@pytest.mark.remote
def test_entry_webpage_info_content(client: FlaskClient):
    resp = client.get("/eucc/e2a88386bd8e37a6/")
    assert resp.status_code == HTTPStatus.OK
    body = resp.get_data(as_text=True)

    assert "EUCC-3087-2025-0000000001-00000" in _extract_row(body, "Certificate ID")
    assert "Infineon Security Controller IFX_CCI_00000Fh" in _extract_row(body, "Product name")
    assert 'class="eucc-assurance-high"' in _extract_row(body, "Assurance level")
    assert 'class="status-active"' in _extract_row(body, "Status")
    assert "Smartcard Controller" in _extract_row(body, "Product type")
    assert "Infineon Technologies AG" in _extract_row(body, "Certificate holder name")
    assert "bodyNumber:3087" in _extract_row(body, "NANDO ID of the CB")
    assert "CC:2022 Revision 1" in _extract_row(body, "CC Version")
    assert "CEM:2022 Revision 1" in _extract_row(body, "CEM Version")

    enisa_link = re.search(
        r'<a[^>]*href="https://certification\.enisa\.europa\.eu/certificates/[^"]*"[^>]*>.*?</a>', body, re.DOTALL
    )
    assert enisa_link, "ENISA certificate webpage link not found"
    assert "EUCC-3087-2025-0000000001-00000" in enisa_link.group(0)
    assert "Certificate webpage" in enisa_link.group(0)


@pytest.mark.remote
def test_entry_webpage_info_package_augmentation(client: FlaskClient):
    resp = client.get("/eucc/e2a88386bd8e37a6/")
    body = resp.get_data(as_text=True)

    assert 'data-cs-name="Package"' in body
    assert '<abbr title="Evaluation assurance level 5">EAL5</abbr>' in body
    assert '<abbr title="Evaluation assurance level 6">EAL6</abbr>' in body
    assert "augmented with" in body
    assert "AVA_VAN.5" in body


@pytest.mark.remote
def test_entry_heuristics_extracted_sars(client: FlaskClient):
    hashid_with_sars = "e2a88386bd8e37a6"
    hashid_without_sars = "53b64420fca6367c"

    resp = client.get(f"/eucc/{hashid_with_sars}/")
    body = resp.get_data(as_text=True)
    assert 'data-cs-name="Extracted SARs"' in body
    assert "AVA_VAN.5" in body

    resp = client.get(f"/eucc/{hashid_without_sars}/")
    body = resp.get_data(as_text=True)
    assert 'data-cs-name="Extracted SARs"' not in body


@pytest.mark.remote
def test_entry_heuristics_scheme_data(client: FlaskClient):
    hashid_with_scheme_data = "e2a88386bd8e37a6"
    hashid_without_scheme_data = "99e8c5452de28e19"

    resp = client.get(f"/eucc/{hashid_with_scheme_data}/")
    body = resp.get_data(as_text=True)
    assert 'data-cs-name="Scheme data"' in body
    assert 'data-cs-name="Scheme data - Vendor"' in body
    assert 'data-cs-name="Scheme data - Url"' in body
    assert "https://www.bsi.bund.de/SharedDocs/Zertifikate_CC/CC/SmartCards_IC_Cryptolib/1079.html" in body
    assert 'data-cs-name="Scheme data - Enhanced - Applicant"' in body

    resp = client.get(f"/eucc/{hashid_without_scheme_data}/")
    body = resp.get_data(as_text=True)
    assert 'data-cs-name="Scheme data"' not in body


@pytest.mark.remote
def test_entry_heuristics_protection_profiles(client: FlaskClient, clean_mongo):
    hashid = "53b64420fca6367c"
    pp_id = "ecc28509c30de1a5"
    mongo.db.eucc.update_one(
        {"_id": hashid},
        {"$set": {"heuristics.protection_profiles": {"_type": "set", "_value": [pp_id]}}},
    )

    resp = client.get(f"/eucc/{hashid}/")
    assert resp.status_code == HTTPStatus.OK
    body = resp.get_data(as_text=True)
    assert 'data-cs-name="Protection profiles"' in body
    assert f'href="/pp/{pp_id}/"' in body
    assert "Card Operating System Generation 2" in body


@pytest.mark.remote
def test_entry_heuristics_related_cves(client: FlaskClient, clean_mongo):
    hashid = "53b64420fca6367c"
    cve_id = "CVE-2019-15807"
    mongo.db.eucc.update_one(
        {"_id": hashid},
        {"$set": {"heuristics.related_cves": {"_type": "set", "_value": [cve_id]}}},
    )

    resp = client.get(f"/eucc/{hashid}/")
    assert resp.status_code == HTTPStatus.OK
    body = resp.get_data(as_text=True)
    assert 'data-cs-name="Related CVEs"' in body
    assert f'href="/vuln/cve/{cve_id}"' in body
    assert "MEDIUM" in body


@pytest.mark.remote
def test_entry_heuristics_cpe_matches(client: FlaskClient, clean_mongo):
    hashid = "9482bdc74476354a"
    cpe_uri = "cpe:2.3:o:tecsec:armored_card:108.0264.0001:*:*:*:*:*:*:*"
    mongo.db.eucc.update_one(
        {"_id": hashid},
        {"$set": {"heuristics.cpe_matches": {"_type": "set", "_value": [cpe_uri]}}},
    )

    resp = client.get(f"/eucc/{hashid}/")
    assert resp.status_code == HTTPStatus.OK
    body = resp.get_data(as_text=True)
    assert 'data-cs-name="CPE matches"' in body
    assert cpe_uri in body
