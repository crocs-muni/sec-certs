from datetime import datetime, timezone

from flask.testing import FlaskClient
from flask_login import current_user

from sec_certs_page import mongo
from sec_certs_page.user.models import User, hash_password


def test_login(client: FlaskClient, username, password, mocker):
    mocker.patch("flask_wtf.csrf.validate_csrf")

    resp = client.get("/user/login")
    assert resp.status_code == 200

    resp = client.post(
        "/user/login",
        data={"username": username, "password": password, "remember_me": True},
        follow_redirects=True,
    )
    assert resp.status_code == 200


def test_magic_link_request(client: FlaskClient, email, mocker, request):
    mocker.patch("flask_wtf.csrf.validate_csrf")
    mock_actor = mocker.Mock()
    mock_actor.send = mocker.Mock()
    mocker.patch("sec_certs_page.user.views.send_magic_link_email", mock_actor)

    resp = client.get("/user/magic-link", follow_redirects=True)
    assert resp.status_code == 200
    assert not mock_actor.send.called

    resp = client.post("/user/magic-link", data={"email": email}, follow_redirects=True)
    assert resp.status_code == 200
    assert mock_actor.send.called


def test_magic_link_login(client: FlaskClient, username, email, request):
    token = User.generate_magic_link_token(username)
    request.addfinalizer(lambda: mongo.db.email_tokens.delete_one({"token": token}))

    resp = client.get("/user/magic-login/" + token, follow_redirects=True)
    assert resp.status_code == 200
    assert current_user.is_authenticated


def test_register(client: FlaskClient, mocker, request):
    mocker.patch("flask_wtf.csrf.validate_csrf")
    mock_actor = mocker.Mock()
    mock_actor.send = mocker.Mock()
    mocker.patch("sec_certs_page.user.views.send_confirmation_email", mock_actor)

    resp = client.get("/user/register")
    assert resp.status_code == 200
    assert not mock_actor.send.called

    request.addfinalizer(lambda: mongo.db.users.delete_many({"username": "newuser"}))
    resp = client.post(
        "/user/register",
        data={
            "username": "newuser",
            "email": "test@example.com",
            "password": "newpassword",
            "password_confirm": "newpassword",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert mock_actor.send.called
    users = list(mongo.db.users.find({"username": "newuser"}))
    assert len(users) == 1


def test_profile(logged_in):
    resp = logged_in.get("/user/profile")
    assert resp.status_code == 200


def test_forget_password(client: FlaskClient, email, mocker):
    mocker.patch("flask_wtf.csrf.validate_csrf")
    mock_actor = mocker.Mock()
    mock_actor.send = mocker.Mock()
    mocker.patch("sec_certs_page.user.views.send_password_reset_email", mock_actor)

    resp = client.get("/user/forgot-password")
    assert resp.status_code == 200
    assert not mock_actor.send.called

    resp = client.post(
        "/user/forgot-password",
        data={"email": email},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert mock_actor.send.called


def test_change_password(logged_in, password, mocker):
    mocker.patch("flask_wtf.csrf.validate_csrf")
    mock_actor = mocker.Mock()
    mock_actor.send = mocker.Mock()
    mocker.patch("sec_certs_page.user.views.send_password_reset_email", mock_actor)

    resp = logged_in.get("/user/change-password", follow_redirects=True)
    assert resp.status_code == 200
    assert mock_actor.send.called


def test_reset_password(client: FlaskClient, username, mocker, request):
    mocker.patch("flask_wtf.csrf.validate_csrf")
    token = User.generate_password_reset_token(username)
    request.addfinalizer(lambda: mongo.db.email_tokens.delete_one({"token": token}))

    resp = client.get("/user/reset-password/" + token)
    assert resp.status_code == 200

    resp = client.post(
        "/user/reset-password/" + token,
        data={"password": "newpassword", "password_confirm": "newpassword"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    user = User.get(username)
    assert user is not None
    assert user.check_password("newpassword")


def test_confirm_email(client: FlaskClient, request):
    username = "user"
    password = "password"
    email = "example@example.com"
    roles: list[str] = []
    pwhash = hash_password(password)
    user = User(
        username, pwhash, email, roles, email_confirmed=False, created_at=datetime.now(timezone.utc), github_id=None
    )
    res = mongo.db.users.insert_one(user.dict)
    request.addfinalizer(lambda: mongo.db.users.delete_one({"_id": res.inserted_id}))
    token = User.generate_confirmation_token(username)
    request.addfinalizer(lambda: mongo.db.email_tokens.delete_one({"token": token}))

    resp = client.get("/user/confirm-email/" + token, follow_redirects=True)
    assert resp.status_code == 200
    updated_user = mongo.db.users.find_one({"username": username})
    assert updated_user["email_confirmed"] is True
    assert mongo.db.email_tokens.find_one({"token": token}) is None


def test_logout(logged_in):
    resp = logged_in.get("/user/logout", follow_redirects=True)
    assert resp.status_code == 200


def test_delete_account(logged_in: FlaskClient, username, mocker, request):
    mocker.patch("flask_wtf.csrf.validate_csrf")
    present = mongo.db.users.find_one({"username": username})
    request.addfinalizer(lambda: mongo.db.users.insert_one(present))
    resp = logged_in.post(
        "/user/delete-account",
        follow_redirects=True,
    )
    assert resp.status_code == 200
    users = list(mongo.db.users.find({"username": username}))
    assert len(users) == 0
