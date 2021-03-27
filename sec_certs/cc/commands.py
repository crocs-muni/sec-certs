import json
from hashlib import blake2b
from operator import itemgetter
from pprint import pprint

import click
import pymongo
from pymongo.errors import BulkWriteError
from tqdm import tqdm

from .. import mongo
from . import cc
from ..utils import remove_dots, add_dots


def _load_certs(file):
    click.echo("Loading certs...")
    data = file.read()
    cc_data = json.loads(data)
    del data
    for key, val in tqdm(cc_data.items()):
        val["_id"] = blake2b(key.encode(), digest_size=10).hexdigest()
        cc_data[key] = remove_dots(val)
    click.echo("Loaded certs")
    return cc_data


@cc.cli.command("import", help="Import CC certs.")
@click.argument("file", type=click.File())
def add(file):
    cc_data = _load_certs(file)

    click.echo("Inserting...")
    try:
        inserted = mongo.db.cc.insert_many(list(cc_data.values()))
        click.echo(f"Inserted {len(inserted.inserted_ids)}")
    except BulkWriteError as e:
        click.echo(f"Couldn't insert: {e}")


@cc.cli.command("update", help="Update CC certs.")
@click.option("-r", "--remove", is_flag=True, help="Remove certs not present in the update file.")
@click.argument("file", type=click.File())
def update(file, remove):
    cc_data = _load_certs(file)
    if remove:
        new_ids = set(map(itemgetter("_id"), cc_data.values()))
        current_ids = set(map(itemgetter("_id"), mongo.db.cc.find({}, ["_id"])))
        old_ids = current_ids.difference(new_ids)
        if old_ids:
            click.echo(f"Found {len(old_ids)} certs not present in the update")
            click.echo("Removing...")
            for idd in tqdm(old_ids):
                mongo.db.cc.delete_one({"_id": idd})
            click.echo("Removed")
        else:
            click.echo("Did not find certs to remove")

    click.echo("Updating...")
    for doc in tqdm(cc_data.values()):
        mongo.db.cc.replace_one({"_id": doc["_id"]}, doc, True)
    click.echo(f"Updated")


@cc.cli.command("create", help="Create the DB of CC certs.")
def create():
    click.echo("Creating...")
    mongo.db.create_collection("cc")
    mongo.db.cc.create_index([("csv_scan.cert_item_name", pymongo.TEXT)])
    click.echo("Created")


@cc.cli.command("drop", help="Drop the DB of CC certs.")
def drop():
    click.echo("Dropping...")
    mongo.db.cc.drop()
    click.echo("Dropped")


@cc.cli.command("query", help="Query the MongoDB for certs.")
@click.argument("query", type=json.loads)
def query(query):
    docs = mongo.db.cc.find(query)
    for doc in docs:
        pprint(add_dots(doc), indent=2)
