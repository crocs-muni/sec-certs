import json
import os
import subprocess
import tempfile
from importlib import resources

import pytest
from bson.json_util import object_hook
from flask import Flask
from pymongo import MongoClient

from sec_certs_page import app as sec_certs_app
from sec_certs_page import mongo
from sec_certs_page.cc.mongo import create as cc_create
from sec_certs_page.common.mongo import init_collections
from sec_certs_page.fips.mongo import create as fips_create
from sec_certs_page.pp.mongo import create as pp_create

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


@pytest.fixture(scope="function")
def client(app: Flask):
    if os.getenv("TEST_REMOTE"):
        yield RemoteTestClient("https://sec-certs.org")
    else:
        with app.test_client() as testing_client:
            yield testing_client
