"""FIPS commands."""

import json
from hashlib import blake2b

import click
from tqdm import tqdm

from .. import mongo
from ..commands import _create, _drop, _query, _status
from . import fips


@fips.cli.command("create", help="Create the DB of FIPS 140 certs.")
def create():  # pragma: no cover
    _create("fips", ["web_data.module_name"], ["cert_id"])


@fips.cli.command("drop", help="Drop the DB of FIPS 140 certs.")
def drop():  # pragma: no cover
    _drop(mongo.db.fips)


@fips.cli.command("query", help="Query the MongoDB for certs.")
@click.option("-p", "--projection", type=json.loads, help="Projection to use with the query.")
@click.argument("query", type=json.loads)
def query(query, projection):  # pragma: no cover
    _query(query, projection, mongo.db.fips)


@fips.cli.command("status", help="Print status information for the MongoDB collection.")
def status():  # pragma: no cover
    _status(mongo.db.fips)


@fips.cli.command("import-map", help="Import old FIPS dataset to create URL mapping.")
def import_map():  # pragma: no cover
    for cert in tqdm(list(mongo.db.fips.find({}, {"cert_id": True})), desc="Processing certs"):
        old_id = blake2b(str(cert["cert_id"]).encode(), digest_size=10).hexdigest()
        new_id = cert["_id"]
        mongo.db.fips_old.replace_one({"_id": old_id}, {"_id": old_id, "hashid": new_id}, upsert=True)
