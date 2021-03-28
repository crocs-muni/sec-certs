import json

import click

from .. import mongo
from ..commands import _add, _create, _drop, _query, _update
from . import pp


@pp.cli.command("import", help="Import protection profiles.")
@click.argument("file", type=click.File())
def add(file):
    _add(file, mongo.db.pp, None)


@pp.cli.command("update", help="Update protection profiles.")
@click.option(
    "-r", "--remove", is_flag=True, help="Remove protection profiles not present in the update file."
)
@click.argument("file", type=click.File())
def update(file, remove):
    _update(file, remove, mongo.db.pp, None)


@pp.cli.command("create", help="Create the DB of protection profiles.")
def create():
    _create("pp", "csv_scan.cc_pp_name")


@pp.cli.command("drop", help="Drop the DB of protection profiles.")
def drop():
    _drop(mongo.db.pp)


@pp.cli.command("query", help="Query the MongoDB for protection profiles.")
@click.option("-p", "--projection", type=json.loads, help="Projection to use with the query.")
@click.argument("query", type=json.loads)
def query(query, projection):
    _query(query, projection, mongo.db.pp)
