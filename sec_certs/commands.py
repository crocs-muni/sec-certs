import json
from hashlib import blake2b
from operator import itemgetter
from pprint import pprint

import click
import pymongo
from pymongo.errors import BulkWriteError
from tqdm import tqdm

from . import mongo
from .utils import add_dots, remove_dots


def _load_certs(file, certs_path):
    click.echo("Loading certs...")
    data = file.read()
    certs = json.loads(data)
    del data
    if certs_path:
        for name in certs_path:
            certs = certs[name]
    for key, val in tqdm(certs.items()):
        val["_id"] = blake2b(key.encode(), digest_size=10).hexdigest()
        certs[key] = remove_dots(val)
    click.echo("Loaded certs")
    return certs


def _add(file, collection, certs_path):
    cert_data = _load_certs(file, certs_path)

    click.echo("Inserting...")
    try:
        inserted = collection.insert_many(list(cert_data.values()))
        click.echo(f"Inserted {len(inserted.inserted_ids)}")
    except BulkWriteError as e:
        click.echo(f"Couldn't insert: {e}")


def _update(file, remove, collection, certs_path):
    cert_data = _load_certs(file, certs_path)
    if remove:
        new_ids = set(map(itemgetter("_id"), cert_data.values()))
        current_ids = set(map(itemgetter("_id"), collection.find({}, ["_id"])))
        old_ids = current_ids.difference(new_ids)
        if old_ids:
            click.echo(f"Found {len(old_ids)} certs not present in the update")
            click.echo("Removing...")
            for idd in tqdm(old_ids):
                collection.delete_one({"_id": idd})
            click.echo("Removed")
        else:
            click.echo("Did not find certs to remove")

    click.echo("Updating...")
    for doc in tqdm(cert_data.values()):
        collection.replace_one({"_id": doc["_id"]}, doc, True)
    click.echo(f"Updated")


def _create(collection_name, text_attr):
    click.echo("Creating...")
    mongo.db.create_collection(collection_name)
    mongo.db[collection_name].create_index([(text_attr, pymongo.TEXT)])
    mongo.db[collection_name].create_index([(text_attr, pymongo.ASCENDING)])
    click.echo("Created")


def _drop(collection):
    click.echo("Dropping...")
    collection.drop()
    click.echo("Dropped")


def _query(query, projection, collection):
    docs = collection.find(query, projection=projection)
    for doc in docs:
        print(json.dumps(add_dots(doc), indent=2))
