"""EUCC commands."""

import json

import click

from . import eucc
from .mongo import create as create_collection
from .mongo import drop as drop_collection
from .mongo import query as query_collection
from .tasks import update_kb as update_kb_core
from .. import mongo
from ..common.mongo import collection_status


@eucc.cli.command("create", help="Create the DB of EUCC certs.")
def create():  # pragma: no cover
    create_collection()


@eucc.cli.command("drop", help="Drop the DB of EUCC certs.")
def drop():  # pragma: no cover
    drop_collection()


@eucc.cli.command("query", help="Query the MongoDB for certs.")
@click.option("-p", "--projection", type=json.loads, help="Projection to use with the query.")
@click.argument("query", type=json.loads)
def query(query, projection):  # pragma: no cover
    docs = query_collection(query, projection)
    for doc in docs:
        print(json.dumps(doc, indent=2))


@eucc.cli.command("status", help="Print status information for the MongoDB collection.")
def status():  # pragma: no cover
    collection_status(mongo.db.eucc)


@eucc.cli.command("update-kb", help="Update the KB of EUCC certs.")
def update_kb():
    ids = list(map(lambda doc: doc["_id"], mongo.db.eucc.find({}, {"_id": 1})))
    reports = [(dgst, "report", None) for dgst in ids]
    targets = [(dgst, "target", None) for dgst in ids]
    update_kb_core(reports + targets)
