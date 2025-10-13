from datetime import datetime, timezone

import pytest
from flask.testing import FlaskClient

from sec_certs_page import mongo
from sec_certs_page.admin import User, hash_password


@pytest.fixture
def admin(app):
    username = "admin"
    password = "password"
    email = "example@example.com"
    roles = ["admin"]
    pwhash = hash_password(password)
    user = User(
        username, pwhash, email, roles, email_confirmed=True, created_at=datetime.now(timezone.utc), github_id=None
    )
    res = mongo.db.users.insert_one(user.dict)
    yield user, password
    mongo.db.users.delete_one({"_id": res.inserted_id})


@pytest.fixture
def logged_in_client(client: FlaskClient, admin, mocker):
    user, password = admin
    mocker.patch("flask_wtf.csrf.validate_csrf")
    with client.post(
        "/user/login",
        data={"username": user.username, "password": password, "remember_me": True},
        follow_redirects=True,
    ):
        yield client


def test_login(client: FlaskClient, admin, mocker):
    user, password = admin
    mocker.patch("flask_wtf.csrf.validate_csrf")

    resp = client.get("/user/login")
    assert resp.status_code == 200

    resp = client.post(
        "/user/login",
        data={"username": user.username, "password": password, "remember_me": True},
        follow_redirects=True,
    )
    assert resp.status_code == 200


def test_logout(logged_in_client):
    resp = logged_in_client.get("/user/logout", follow_redirects=True)
    assert resp.status_code == 200


def test_home(logged_in_client):
    resp = logged_in_client.get("/admin/")
    assert resp.status_code == 200


def test_updates(logged_in_client):
    resp = logged_in_client.get("/admin/updates")
    assert resp.status_code == 200


def test_update(logged_in_client):
    id = list(mongo.db.cc_log.find({}, {"_id": True}))[-1]["_id"]
    resp = logged_in_client.get(f"/admin/update/{id}")
    assert resp.status_code == 200

    id = list(mongo.db.fips_log.find({}, {"_id": True}))[-1]["_id"]
    resp = logged_in_client.get(f"/admin/update/{id}")
    assert resp.status_code == 200


def test_update_diff(logged_in_client):
    id = list(mongo.db.cc_diff.find({}, {"_id": True}))[-1]["_id"]
    resp = logged_in_client.get(f"/admin/update/diff/{id}")
    assert resp.status_code == 200

    id = list(mongo.db.fips_diff.find({}, {"_id": True}))[-1]["_id"]
    resp = logged_in_client.get(f"/admin/update/diff/{id}")
    assert resp.status_code == 200
