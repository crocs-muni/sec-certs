import json
import click

from .. import mongo
from . import cc
from ..commands import _add, _update, _create, _drop, _query


@cc.cli.command("import", help="Import CC certs.")
@click.argument("file", type=click.File())
def add(file):
    _add(file, mongo.db.cc, None)


@cc.cli.command("update", help="Update CC certs.")
@click.option(
    "-r", "--remove", is_flag=True, help="Remove certs not present in the update file."
)
@click.argument("file", type=click.File())
def update(file, remove):
    _update(file, remove, mongo.db.cc, None)


@cc.cli.command("create", help="Create the DB of CC certs.")
def create():
    _create("cc", "csv_scan.cert_item_name")


@cc.cli.command("drop", help="Drop the DB of CC certs.")
def drop():
    _drop(mongo.db.cc)


@cc.cli.command("query", help="Query the MongoDB for certs.")
@click.argument("query", type=json.loads)
def query(query):
    _query(query, mongo.db.cc)
