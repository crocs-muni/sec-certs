import pytest
from flask import url_for
from flask.testing import FlaskClient
from pytest_mock import MockerFixture

from sec_certs_page import mongo


@pytest.fixture()
def certificate():
    return mongo.db.cc.find_one({"_id": "6ca52f5450bedb2f"})


@pytest.fixture()
def sub_obj(certificate):
    return {
        "selected": [
            {
                "name": certificate["name"],
                "hashid": certificate["_id"],
                "type": "cc",
                "url": url_for("cc.entry", hashid=certificate["_id"]),
            }
        ],
        "email": "example@example.com",
        "updates": "all",
        "captcha": "...",
    }


@pytest.fixture()
def sub_obj_new(certificate):
    return {
        "selected": None,
        "email": "example@example.com",
        "updates": "new",
        "captcha": "...",
    }


@pytest.fixture
def unconfirmed_subscription(client: FlaskClient, mocker: MockerFixture, sub_obj):
    mocker.patch("sec_certs_page.common.views.validate_captcha")
    mocker.patch("flask_wtf.csrf.validate_csrf")
    mocker.patch("dramatiq.Actor.send")
    client.post("/notify/subscribe/", json=sub_obj)
    subscription = mongo.db.subs.find_one({"email": sub_obj["email"]})
    yield subscription
    mongo.db.subs.delete_one({"_id": subscription["_id"]})


@pytest.fixture
def confirmed_subscription(client: FlaskClient, unconfirmed_subscription):
    client.get(f"/notify/confirm/{unconfirmed_subscription['token']}")
    subscription = mongo.db.subs.find_one({"_id": unconfirmed_subscription["_id"]})
    yield subscription
    mongo.db.subs.delete_one({"_id": subscription["_id"]})


def test_subscribe(client: FlaskClient, mocker: MockerFixture, sub_obj):
    mocker.patch("sec_certs_page.common.views.validate_captcha")
    mocker.patch("flask_wtf.csrf.validate_csrf")
    at = mocker.patch("dramatiq.Actor.send")
    resp = client.post("/notify/subscribe/", json=sub_obj)
    assert resp.status_code == 200
    assert resp.is_json
    assert resp.json == {"status": "OK"}
    subscription = mongo.db.subs.find_one({"email": sub_obj["email"]})
    assert subscription
    assert subscription["token"]
    assert subscription["timestamp"]
    at.assert_called_once_with(subscription["token"])
    mongo.db.subs.delete_one({"email": sub_obj["email"]})


def test_subscribe_new(client: FlaskClient, mocker: MockerFixture, sub_obj_new):
    mocker.patch("sec_certs_page.common.views.validate_captcha")
    mocker.patch("flask_wtf.csrf.validate_csrf")
    at = mocker.patch("dramatiq.Actor.send")
    resp = client.post("/notify/subscribe/", json=sub_obj_new)
    assert resp.status_code == 200
    assert resp.is_json
    assert resp.json == {"status": "OK"}
    subscription = mongo.db.subs.find_one({"email": sub_obj_new["email"]})
    assert subscription
    assert subscription["token"]
    assert subscription["timestamp"]
    at.assert_called_once_with(subscription["token"])
    mongo.db.subs.delete_one({"email": sub_obj_new["email"]})


def test_bad_subscribe(client: FlaskClient, mocker: MockerFixture):
    mocker.patch("sec_certs_page.common.views.validate_captcha")
    mocker.patch("flask_wtf.csrf.validate_csrf")
    at = mocker.patch("dramatiq.Actor.send")
    resp = client.post("/notify/subscribe/", json={"email": "..."})
    assert resp.status_code == 400
    at.assert_not_called()
    resp = client.post(
        "/notify/subscribe/", json={"email": "bad-email", "selected": "...", "updates": "...", "captcha": "..."}
    )
    assert resp.status_code == 400
    at.assert_not_called()
    resp = client.post(
        "/notify/subscribe/",
        json={"email": "example@example.com", "selected": "...", "updates": "bad", "captcha": "..."},
    )
    assert resp.status_code == 400
    at.assert_not_called()
    resp = client.post(
        "/notify/subscribe/",
        json={"email": "example@example.com", "selected": [{"some": "bad"}], "updates": "all", "captcha": "..."},
    )
    assert resp.status_code == 400
    at.assert_not_called()
    resp = client.post(
        "/notify/subscribe/",
        json={
            "email": "example@example.com",
            "selected": [{"hashid": "...", "name": "...", "url": "...", "type": "bad"}],
            "updates": "all",
            "captcha": "...",
        },
    )
    assert resp.status_code == 400
    at.assert_not_called()
    resp = client.post(
        "/notify/subscribe/",
        json={
            "email": "example@example.com",
            "selected": [{"hashid": "bad", "name": "...", "url": "...", "type": "fips"}],
            "updates": "all",
            "captcha": "...",
        },
    )
    assert resp.status_code == 400
    at.assert_not_called()
    resp = client.post(
        "/notify/subscribe/",
        json={
            "email": "example@example.com",
            "selected": [{"hashid": "b906b2e8d7617202", "name": 5, "url": "...", "type": "cc"}],
            "updates": "all",
            "captcha": "...",
        },
    )
    assert resp.status_code == 400
    at.assert_not_called()


def test_confirm(client: FlaskClient, unconfirmed_subscription):
    resp = client.get(f"/notify/confirm/{unconfirmed_subscription['token']}")
    assert resp.status_code == 200
    sub = mongo.db.subs.find_one({"_id": unconfirmed_subscription["_id"]})
    assert sub["confirmed"]


def test_manage(client: FlaskClient, confirmed_subscription, mocker: MockerFixture):
    mocker.patch("flask_wtf.csrf.validate_csrf")
    resp = client.get(f"/notify/manage/{confirmed_subscription['email_token']}")
    assert resp.status_code == 200
    data = {
        "certificates-0-certificate_hashid": confirmed_subscription["certificate"]["hashid"],
        "certificates-0-subscribe": "y",
        "certificates-0-updates": "vuln",
        "new": "y",
    }
    resp = client.post(f"/notify/manage/{confirmed_subscription['email_token']}", data=data, follow_redirects=True)
    assert resp.status_code == 200
    new_sub = mongo.db.subs.find_one({"email_token": confirmed_subscription["email_token"], "updates": "new"})
    assert new_sub is not None
    data = {
        "certificates-0-certificate_hashid": confirmed_subscription["certificate"]["hashid"],
        "certificates-0-subscribe": "y",
        "certificates-0-updates": "vuln",
    }
    resp = client.post(f"/notify/manage/{confirmed_subscription['email_token']}", data=data, follow_redirects=True)
    assert resp.status_code == 200
    new_sub = mongo.db.subs.find_one({"email_token": confirmed_subscription["email_token"], "updates": "new"})
    assert new_sub is None
    sub = mongo.db.subs.find_one({"_id": confirmed_subscription["_id"]})
    assert sub["updates"] == "vuln"
    del data["certificates-0-subscribe"]
    resp = client.post(f"/notify/manage/{confirmed_subscription['email_token']}", data=data, follow_redirects=True)
    assert resp.status_code == 200
    sub = mongo.db.subs.find_one({"_id": confirmed_subscription["_id"]})
    assert sub is None


def test_unsubscribe_single(client: FlaskClient, confirmed_subscription):
    resp = client.get(f"/notify/unsubscribe/{confirmed_subscription['token']}")
    assert resp.status_code == 200
    sub = list(mongo.db.subs.find({"_id": confirmed_subscription["_id"]}))
    assert not sub


def test_unsubscribe_all(client: FlaskClient, confirmed_subscription):
    resp = client.get(f"/notify/unsubscribe/all/{confirmed_subscription['email_token']}")
    assert resp.status_code == 200
    sub = list(mongo.db.subs.find({"_id": confirmed_subscription["_id"]}))
    assert not sub


def test_unsubscribe_request(client: FlaskClient, confirmed_subscription, mocker: MockerFixture):
    mocker.patch("flask_wtf.csrf.validate_csrf")
    at = mocker.patch("dramatiq.Actor.send")
    resp = client.get("/notify/unsubscribe/request/")
    assert resp.status_code == 200
    resp = client.post("/notify/unsubscribe/request/", data={"email": confirmed_subscription["email"]})
    exists_content = resp.data
    assert resp.status_code == 200
    at.assert_called_once_with(confirmed_subscription["email"])
    resp = client.post("/notify/unsubscribe/request/", data={"email": "aaaa@bbbb.com"})
    doesnt_exist_content = resp.data
    assert resp.status_code == 200
    assert exists_content == doesnt_exist_content
