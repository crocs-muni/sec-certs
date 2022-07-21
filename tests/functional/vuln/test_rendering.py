import random

import pytest
from flask.testing import FlaskClient

from sec_certs_page import mongo


@pytest.mark.remote
def test_index(client: FlaskClient):
    resp = client.get("/vuln/")
    assert resp.status_code == 200


@pytest.mark.remote
def test_cve(client: FlaskClient):
    resp = client.get("/vuln/cve/CVE-2019-15809")
    assert resp.status_code == 200


def test_cve_random(client: FlaskClient):
    all_cves = list(mongo.db.cve.find({}, {"_id": True}))
    for _ in range(100):
        cve = random.choice(all_cves)
        resp = client.get(f"/vuln/cve/{cve['_id']}")
        assert resp.status_code == 200


@pytest.mark.remote
def test_cpe(client: FlaskClient):
    resp = client.get("/vuln/cpe/cpe:2.3:o:tecsec:armored_card:108.0264.0001:*:*:*:*:*:*:*")
    assert resp.status_code == 200
    resp = client.get("/vuln/cpe/cpe:2.3:a:%5C%40thi.ng%5C/egf_project:%5C%40thi.ng%5C/egf:0.2.1:*:*:*:*:node.js:*:*")
    assert resp.status_code == 200


def test_cpe_random(client: FlaskClient):
    all_cpes = list(mongo.db.cpe.find({}, {"_id": True}))
    for _ in range(100):
        cpe = random.choice(all_cpes)
        resp = client.get(f"/vuln/cpe/{cpe['_id']}")
        assert resp.status_code == 200
