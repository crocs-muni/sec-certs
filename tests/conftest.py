import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from importlib import resources
from typing import Any, Generator

import pytest
from bson.json_util import object_hook
from flask import Flask
from flask.testing import FlaskClient
from pymongo import MongoClient

from sec_certs_page import app as sec_certs_app
from sec_certs_page import mongo
from sec_certs_page.cc.mongo import create as cc_create
from sec_certs_page.common.mongo import init_collections
from sec_certs_page.fips.mongo import create as fips_create
from sec_certs_page.pp.mongo import create as pp_create
from sec_certs_page.user.models import User, hash_password

from .client import RemoteTestClient


@pytest.fixture(scope="session")
def app():
    with sec_certs_app.app_context():
        yield sec_certs_app


@pytest.fixture(scope="session")
def mongodb(app):
    # Spin-up a temporary MongoDB instance
    # Requires `mongod` to be installed and in PATH
    # This is used instead of mongomock because mongomock does not support all features
    # required by the application (e.g., $text search)
    tmpdir = tempfile.TemporaryDirectory()
    proc = subprocess.Popen(
        [
            "mongod",
            "--dbpath",
            tmpdir.name,
            "--replSet",
            "rs0",
            "--port",
            "27666",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        cx = MongoClient("mongodb://localhost:27666", directConnection=True)
        cx.admin.command("replSetInitiate")
        yield cx
    finally:
        proc.kill()
        proc.wait()
        tmpdir.cleanup()


@pytest.fixture(autouse=True, scope="session")
def mongo_data(app, mongodb):
    # Create the DB structure
    cc_create()
    fips_create()
    pp_create()
    # Initialize other collections
    init_collections()
    for file in resources.files("tests.functional.data.mongo").iterdir():
        if not file.name.endswith(".json"):
            continue
        with file.open("r") as f:
            data = json.load(f, object_hook=object_hook)
        collection = file.name.removesuffix(".json")
        mongo.db[collection].insert_many(data)
    yield


# @pytest.fixture(autouse=True, scope="function")
def clean_mongo(app):
    with mongo.db.watch(full_document_before_change="whenAvailable") as stream:
        yield
        # Clean up any changes made to the DB during the test
        while stream.alive:
            change = stream.try_next()
            if not change:
                break
            operation = change["operationType"]
            pre_image = change.get("fullDocumentBeforeChange")
            doc_id = change["documentKey"]["_id"]
            coll = mongo.db[change["ns"]["coll"]]

            if operation == "update" or operation == "replace":
                if pre_image:
                    # Restore the previous version of the document
                    coll.replace_one({"_id": doc_id}, pre_image)
                    print(f"Rolled back update/replace for _id {doc_id}")
                else:
                    print(f"Pre-image missing for update/replace operation on _id {doc_id}")
            elif operation == "insert":
                # Remove the inserted document
                coll.delete_one({"_id": doc_id})
                print(f"Rolled back insert for _id {doc_id}")
            else:
                print(f"Unknown operationType: {operation} for _id {doc_id}")


@pytest.fixture(scope="function")
def raw_client(app: Flask) -> Generator[FlaskClient | RemoteTestClient, Any, None]:
    if os.getenv("TEST_REMOTE"):
        yield RemoteTestClient("https://sec-certs.org")
    else:
        with app.app_context():
            yield app.test_client()


@pytest.fixture(scope="function")
def client(app: Flask) -> Generator[FlaskClient | RemoteTestClient, Any, None]:
    if os.getenv("TEST_REMOTE"):
        yield RemoteTestClient("https://sec-certs.org")
    else:
        with app.app_context(), app.test_client() as testing_client:
            yield testing_client


@pytest.fixture()
def user(app) -> Generator[tuple[User, str], Any, None]:
    username = "user"
    password = "password"
    email = "example@example.com"
    roles: list[str] = []
    pwhash = hash_password(password)
    user = User(
        username, pwhash, email, roles, email_confirmed=True, created_at=datetime.now(timezone.utc), github_id=None
    )
    res = mongo.db.users.insert_one(user.dict)
    yield user, password
    mongo.db.users.delete_one({"_id": res.inserted_id})


@pytest.fixture()
def username(user):
    user, _ = user
    return user.username


@pytest.fixture()
def email(user):
    user, _ = user
    return user.email


@pytest.fixture()
def password(user):
    _, password = user
    return password


@pytest.fixture()
def logged_in(raw_client: FlaskClient, username, password, mocker) -> Generator[FlaskClient, Any, None]:
    mocker.patch("flask_wtf.csrf.validate_csrf")
    with raw_client:
        raw_client.post(
            "/user/login",
            data={"username": username, "password": password, "remember_me": True},
            follow_redirects=True,
        )
        yield raw_client
