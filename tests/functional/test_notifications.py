from datetime import datetime, timezone

import pytest
from flask import url_for
from flask.testing import FlaskClient
from pytest_mock import MockerFixture

from sec_certs_page import mongo


@pytest.fixture()
def certificate(mongo_data):
    return mongo.db.cc.find_one({"_id": "6ca52f5450bedb2f"})


def test_subscribe_changes(request, user, logged_in: FlaskClient, mocker: MockerFixture, certificate):
    user, password = user
    mocker.patch("flask_wtf.csrf.validate_csrf")
    sub_obj = {
        "cert": {
            "name": certificate["name"],
            "hashid": certificate["dgst"],
            "type": "cc",
            "url": url_for("cc.entry", hashid=certificate["dgst"]),
        },
        "updates": "all",
    }
    resp = logged_in.post("/notify/subscribe/", json=sub_obj)
    assert resp.status_code == 200
    assert resp.is_json
    assert resp.json == {"status": "OK"}

    sub = mongo.db.subs.find_one({"username": user.username})
    request.addfinalizer(lambda: mongo.db.subs.delete_one({"_id": sub["_id"]}))
    assert sub
    assert sub["timestamp"]
    assert sub["updates"] == "all"
    assert sub["type"] == "changes"
    assert sub["certificate"]["name"] == certificate["name"]


def test_subscribe_new(request, user, logged_in: FlaskClient, mocker: MockerFixture):
    user, password = user
    mocker.patch("flask_wtf.csrf.validate_csrf")
    sub_obj_new = {
        "which": "cc",
    }
    resp = logged_in.post("/notify/subscribe/new/", json=sub_obj_new)
    assert resp.status_code == 200
    assert resp.is_json
    assert resp.json["status"] == "OK"

    sub = mongo.db.subs.find_one({"username": user.username})
    request.addfinalizer(lambda: mongo.db.subs.delete_one({"_id": sub["_id"]}))
    assert sub
    assert sub["timestamp"]
    assert sub["type"] == "new"
    assert sub["which"] == "cc"


def test_bad_subscribe(user, logged_in: FlaskClient, mocker: MockerFixture):
    mocker.patch("flask_wtf.csrf.validate_csrf")
    resp = logged_in.post("/notify/subscribe/", json={"bad": "keys"})
    assert resp.status_code == 400
    resp = logged_in.post("/notify/subscribe/", json={"cert": "...", "updates": "bad"})
    assert resp.status_code == 400
    resp = logged_in.post(
        "/notify/subscribe/",
        json={"cert": "...", "updates": "all"},
    )
    assert resp.status_code == 400
    resp = logged_in.post(
        "/notify/subscribe/",
        json={"cert": {"a": "bad"}, "updates": "all"},
    )
    assert resp.status_code == 400
    resp = logged_in.post(
        "/notify/subscribe/",
        json={"cert": {"name": "...", "hashid": "...", "url": "...", "type": "bad"}, "updates": "all"},
    )
    assert resp.status_code == 400


def test_bad_subscribe_new(user, logged_in: FlaskClient, mocker: MockerFixture):
    mocker.patch("flask_wtf.csrf.validate_csrf")
    resp = logged_in.post("/notify/subscribe/new/", json="aaa")
    assert resp.status_code == 400
    resp = logged_in.post("/notify/subscribe/", json={"bad": "keys"})
    assert resp.status_code == 400
    resp = logged_in.post(
        "/notify/subscribe/new/",
        json={"which": "bad"},
    )
    assert resp.status_code == 400


@pytest.fixture(scope="function")
def subscription(request, user, certificate):
    user, password = user
    sub = {
        "timestamp": datetime.now(timezone.utc),
        "username": user.username,
        "type": "changes",
        "updates": "all",
        "certificate": {
            "name": certificate["name"],
            "hashid": certificate["dgst"],
            "type": "cc",
            "url": url_for("cc.entry", hashid=certificate["dgst"]),
        },
    }
    res = mongo.db.subs.insert_one(sub)
    sub["_id"] = res.inserted_id
    try:
        yield sub
    finally:
        mongo.db.subs.delete_one({"_id": res.inserted_id})


def test_manage(user, logged_in: FlaskClient, mocker: MockerFixture, subscription):
    user, password = user
    mocker.patch("flask_wtf.csrf.validate_csrf")
    resp = logged_in.get(f"/notify/manage/")
    assert resp.status_code == 200

    data = {
        "new-0-which": "cc",
        "new-0-subscribe": "y",
        "new-1-which": "fips",
        "new-1-subscribe": "y",
        "new-2-which": "pp",
        "new-2-subscribe": "y",
    }
    resp = logged_in.post(f"/notify/manage/", data=data, follow_redirects=True)
    assert resp.status_code == 200
    subs = list(mongo.db.subs.find({"username": user.username}))
    assert len(subs) == 4
    assert all(s["type"] == "new" for s in subs if s["_id"] != subscription["_id"])

    data = {
        "new-0-which": "cc",
        "new-0-subscribe": "",
        "new-1-which": "fips",
        "new-1-subscribe": "",
        "new-2-which": "pp",
        "new-2-subscribe": "",
    }
    resp = logged_in.post(f"/notify/manage/", data=data, follow_redirects=True)
    assert resp.status_code == 200
    subs = list(mongo.db.subs.find({"username": user.username}))
    assert len(subs) == 1
    assert subs[0]["_id"] == subscription["_id"]

    data = {
        "changes-0-certificate_type": subscription["certificate"]["type"],
        "changes-0-certificate_hashid": subscription["certificate"]["hashid"],
        "changes-0-updates": "vuln",
        "changes-0-subscribe": "y",
    }
    resp = logged_in.post(f"/notify/manage/", data=data, follow_redirects=True)
    assert resp.status_code == 200
    sub = mongo.db.subs.find_one({"_id": subscription["_id"]})
    assert sub["updates"] == "vuln"


def test_unsubscribe_single(logged_in: FlaskClient, mocker: MockerFixture, subscription):
    mocker.patch("flask_wtf.csrf.validate_csrf")
    resp = logged_in.post(f"/notify/unsubscribe/", json={"id": str(subscription["_id"])}, follow_redirects=True)
    assert resp.status_code == 200
    sub = list(mongo.db.subs.find({"_id": subscription["_id"]}))
    assert not sub


def test_unsubscribe_all(user, logged_in: FlaskClient, mocker: MockerFixture, subscription):
    user, password = user
    mocker.patch("flask_wtf.csrf.validate_csrf")
    resp = logged_in.post(f"/notify/unsubscribe/all/", follow_redirects=True)
    assert resp.status_code == 200
    sub = list(mongo.db.subs.find({"username": user.username}))
    assert not sub
