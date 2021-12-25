"""Common Criteria commands."""

import json

import click

from .. import mongo
from ..commands import _add, _create, _drop, _query, _status, _update
from . import cc


def mapper(cert):
    return cert


@cc.cli.command("import", help="Import CC certs.")
@click.argument("file", type=click.File())
def add(file):
    _add(file, mongo.db.cc, ["certs"], mapper)


@cc.cli.command("update", help="Update CC certs.")
@click.option("-r", "--remove", is_flag=True, help="Remove certs not present in the update file.")
@click.argument("file", type=click.File())
def update(file, remove):
    _update(file, remove, mongo.db.cc, ["certs"], mapper)


@cc.cli.command("create", help="Create the DB of CC certs.")
def create():
    _create("cc", ["name", "heuristics.cert_id"], [])


@cc.cli.command("drop", help="Drop the DB of CC certs.")
def drop():
    _drop(mongo.db.cc)


@cc.cli.command("query", help="Query the MongoDB for certs.")
@click.option("-p", "--projection", type=json.loads, help="Projection to use with the query.")
@click.argument("query", type=json.loads)
def query(query, projection):
    _query(query, projection, mongo.db.cc)


@cc.cli.command("status", help="Print status information for the MongoDB collection.")
def status():
    _status(mongo.db.cc)
