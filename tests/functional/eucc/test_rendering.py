from http import HTTPStatus

import pytest
from flask.testing import FlaskClient
from sec_certs_page import mongo


@pytest.mark.remote
def test_index(client: FlaskClient):
    resp = client.get("/eucc/")
    assert resp.status_code == HTTPStatus.OK


@pytest.mark.remote
def test_data(client: FlaskClient):
    resp = client.get("/eucc/data/")
    assert resp.status_code == HTTPStatus.OK


@pytest.mark.remote
def test_random(client: FlaskClient):
    for _ in range(100):
        resp = client.get("/eucc/random/", follow_redirects=True)
        assert resp.status_code == HTTPStatus.OK


@pytest.mark.remote
def test_search(client: FlaskClient):
    resp = client.get("/eucc/search/")
    assert resp.status_code == HTTPStatus.FOUND
    resp = client.get("/eucc/mergedsearch/")
    assert resp.status_code == HTTPStatus.OK
    resp = client.get("/eucc/ftsearch/")
    assert resp.status_code == HTTPStatus.FOUND


@pytest.mark.remote
def test_search_redirect_preserves_args(client: FlaskClient):
    resp = client.get("/eucc/search/?query=hardcoded&page=2")
    assert resp.status_code == HTTPStatus.FOUND
    assert "query=hardcoded" in resp.location
    assert "page=2" in resp.location


@pytest.mark.remote
def test_fulltext_search_redirect_params(client: FlaskClient):
    resp = client.get("/eucc/ftsearch/?query=hardcoded")
    assert resp.status_code == HTTPStatus.FOUND
    assert "search_type=fulltext" in resp.location
    assert "query=hardcoded" in resp.location


@pytest.mark.remote
def test_search_valid_status_and_sort(client: FlaskClient):
    resp = client.get("/eucc/mergedsearch/?status=active")
    assert resp.status_code == HTTPStatus.OK
    resp = client.get("/eucc/mergedsearch/?status=archived")
    assert resp.status_code == HTTPStatus.OK
    resp = client.get("/eucc/mergedsearch/?sort_by=cert_id&sort_dir=asc")
    assert resp.status_code == HTTPStatus.OK
    resp = client.get("/eucc/mergedsearch/?sort_by=not_valid_before&sort_dir=desc")
    assert resp.status_code == HTTPStatus.OK


@pytest.mark.remote
def test_entry_old(client: FlaskClient):
    bad_resp = client.get("/eucc/AAAAAAAAAAAAAAAAAAAA/")
    assert bad_resp.status_code == HTTPStatus.NOT_FOUND


@pytest.mark.remote
def test_entry_old_redirect(client: FlaskClient, clean_mongo):
    old_id = "BBBBBBBBBBBBBBBBBBBB"
    new_hashid = "e2a88386bd8e37a6"
    mongo.db.eucc_old.insert_one({"_id": old_id, "hashid": new_hashid})

    resp = client.get(f"/eucc/{old_id}/")
    assert resp.status_code == HTTPStatus.MOVED_PERMANENTLY
    assert resp.location.endswith(f"/eucc/{new_hashid}/")

    followed_resp = client.get(f"/eucc/{old_id}/", follow_redirects=True)
    assert followed_resp.status_code == HTTPStatus.OK

    npath_resp = client.get(f"/eucc/{old_id}/cert.json")
    assert npath_resp.status_code == HTTPStatus.MOVED_PERMANENTLY
    assert npath_resp.location.endswith(f"/eucc/{new_hashid}/cert.json")


@pytest.mark.remote
def test_entry(client: FlaskClient):
    hashid = "e2a88386bd8e37a6"
    cert_id = "EUCC-3087-2025-0000000001-00000"
    cert_name = (
        "Infineon Security Controller IFX_CCI_00000Fh, IFX_CCI_000010h, IFX_CCI_000026h, "
        "IFX_CCI_000027h, IFX_CCI_000028h, IFX_CCI_000029h, IFX_CCI_00002Ah, IFX_CCI_00002Bh, "
        "IFX_CCI_00002Ch in the design step G12"
    )
    hid_resp = client.get(f"/eucc/{hashid}/", follow_redirects=True)
    assert hid_resp.status_code == HTTPStatus.OK

    hid_body = hid_resp.get_data(as_text=True)
    assert cert_id in hid_body
    assert cert_name in hid_body

    cid_resp = client.get(f"/eucc/id/{cert_id}", follow_redirects=True)
    assert cid_resp.status_code == HTTPStatus.OK
    assert len(cid_resp.history) == 1
    assert cid_resp.history[0].location.endswith(f"/eucc/{hashid}/")

    name_resp = client.get(f"/eucc/name/{cert_name}", follow_redirects=True)
    assert name_resp.status_code == HTTPStatus.OK
    assert len(name_resp.history) == 1
    assert name_resp.history[0].location.endswith(f"/eucc/{hashid}/")

    cert_resp = client.get(f"/eucc/{hashid}/cert.json")
    assert cert_resp.status_code == HTTPStatus.OK
    assert cert_resp.is_json
    assert cert_resp.json["cert_id"] == cert_id
    assert cert_resp.json["dgst"] == hashid
    assert client.get(f"/eucc/{hashid}/target.pdf").status_code in (HTTPStatus.OK, HTTPStatus.NOT_FOUND)
    assert client.get(f"/eucc/{hashid}/target.txt").status_code in (HTTPStatus.OK, HTTPStatus.NOT_FOUND)
    assert client.get(f"/eucc/{hashid}/report.pdf").status_code in (HTTPStatus.OK, HTTPStatus.NOT_FOUND)
    assert client.get(f"/eucc/{hashid}/report.txt").status_code in (HTTPStatus.OK, HTTPStatus.NOT_FOUND)
    assert client.get(f"/eucc/{hashid}/cert.pdf").status_code in (HTTPStatus.OK, HTTPStatus.NOT_FOUND)
    assert client.get(f"/eucc/{hashid}/cert.txt").status_code in (HTTPStatus.OK, HTTPStatus.NOT_FOUND)

    bad_resp = client.get("/eucc/AAAAAAAAAAAAAAAA/")
    assert bad_resp.status_code == HTTPStatus.NOT_FOUND

    bad_resp = client.get("/eucc/AAAAAAAAAAAAAAAA/cert.json")
    assert bad_resp.status_code == HTTPStatus.NOT_FOUND

    bad_resp = client.get("/eucc/id/some-bad-id-that-doesnt-exist")
    assert bad_resp.status_code == HTTPStatus.NOT_FOUND

    bad_resp = client.get("/eucc/name/some-bad-name-that-doesnt-exist")
    assert bad_resp.status_code == HTTPStatus.NOT_FOUND


@pytest.mark.remote
def test_compare(client: FlaskClient):
    resp = client.get("/eucc/compare/e2a88386bd8e37a6/5c5769d9a7c92821/")
    assert resp.status_code == HTTPStatus.OK


@pytest.mark.remote
def test_compare_not_found(client: FlaskClient):
    resp = client.get("/eucc/compare/e2a88386bd8e37a6/AAAAAAAAAAAAAAAA/")
    assert resp.status_code == HTTPStatus.NOT_FOUND


@pytest.mark.remote
def test_dataset(client: FlaskClient):
    resp = client.get("/eucc/dataset.json")
    assert resp.status_code in (HTTPStatus.OK, HTTPStatus.NOT_FOUND)


@pytest.mark.remote
def test_dataset_archive(client: FlaskClient):
    resp = client.get("/eucc/eucc.tar.gz")
    assert resp.status_code in (HTTPStatus.OK, HTTPStatus.NOT_FOUND)


@pytest.mark.remote
def test_entry_feed(client: FlaskClient):
    resp = client.get("/eucc/e2a88386bd8e37a6/feed.xml")
    assert resp.status_code == HTTPStatus.OK
    assert resp.mimetype == "application/atom+xml"

    bad_resp = client.get("/eucc/AAAAAAAAAAAAAAAA/feed.xml")
    assert bad_resp.status_code == HTTPStatus.NOT_FOUND


@pytest.mark.remote
def test_entry_feed_content(client: FlaskClient):
    resp = client.get("/eucc/e2a88386bd8e37a6/feed.xml")
    body = resp.get_data(as_text=True)
    assert "Infineon Security Controller" in body


@pytest.mark.remote
def test_entry_json_attachment_header(client: FlaskClient):
    resp = client.get("/eucc/e2a88386bd8e37a6/cert.json")
    assert resp.headers.get("Content-Disposition", "").startswith("attachment")


@pytest.mark.remote
def test_compare_self(client: FlaskClient):
    resp = client.get("/eucc/compare/e2a88386bd8e37a6/e2a88386bd8e37a6/")
    assert resp.status_code == HTTPStatus.OK


@pytest.mark.remote
def test_search_bad(client: FlaskClient):
    resp = client.get("/eucc/mergedsearch/?schemes=zz")
    assert resp.status_code == HTTPStatus.BAD_REQUEST
    resp = client.get("/eucc/mergedsearch/?eal=zz")
    assert resp.status_code == HTTPStatus.BAD_REQUEST
    resp = client.get("/eucc/mergedsearch/?page=bad")
    assert resp.status_code == HTTPStatus.BAD_REQUEST
