import json

import click

from .. import mongo
from ..common.commands import _create, _drop, _query, _status
from . import pp


@pp.cli.command("create", help="Create the DB of protection profiles.")
def create():  # pragma: no cover
    _create("pp", ["web_data.name"], [])


@pp.cli.command("drop", help="Drop the DB of protection profiles.")
def drop():  # pragma: no cover
    _drop(mongo.db.pp)


@pp.cli.command("query", help="Query the MongoDB for protection profiles.")
@click.option("-p", "--projection", type=json.loads, help="Projection to use with the query.")
@click.argument("query", type=json.loads)
def query(query, projection):  # pragma: no cover
    _query(query, projection, mongo.db.pp)


@pp.cli.command("status", help="Print status information for the MongoDB collection.")
def status():  # pragma: no cover
    _status(mongo.db.pp)
