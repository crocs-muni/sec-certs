import json
from hashlib import blake2b
from operator import itemgetter
from pprint import pformat

import click
import pymongo
from pymongo.errors import BulkWriteError
from tqdm import tqdm

from .. import mongo
from ..common.objformats import StorageFormat, WorkingFormat


def _load_certs(file, certs_path, mapper):  # pragma: no cover
    click.echo("Loading certs...")
    data = file.read()
    certs = json.loads(data)
    del data
    if certs_path:
        for name in certs_path:
            certs = certs[name]
    result = {}
    for cert in tqdm(certs.values() if isinstance(certs, dict) else certs):
        if "dgst" in cert and len(cert["dgst"]) == 16:
            cert["_id"] = cert["dgst"]
        else:
            cert["_id"] = blake2b(cert["cert_id"].encode(), digest_size=8).hexdigest()
        result[cert["_id"]] = WorkingFormat(mapper(cert) if mapper else cert).to_storage_format().get()
    click.echo("Loaded certs")
    return result


def _add(file, collection, certs_path, mapper):  # pragma: no cover
    cert_data = _load_certs(file, certs_path, mapper)

    click.echo("Inserting...")
    try:
        inserted = collection.insert_many(list(cert_data.values()))
        click.echo(f"Inserted {len(inserted.inserted_ids)}")
    except BulkWriteError as e:
        click.echo(f"Couldn't insert: {e}")


def _update(file, remove, collection, certs_path, mapper):  # pragma: no cover
    cert_data = _load_certs(file, certs_path, mapper)
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
    click.echo("Updated")


def _create(collection_name, text_attrs, sort_attrs):  # pragma: no cover
    click.echo("Creating...")
    mongo.db.create_collection(collection_name)
    if text_attrs:
        mongo.db[collection_name].create_index([(text_attr, pymongo.TEXT) for text_attr in text_attrs])
    if sort_attrs:
        mongo.db[collection_name].create_index([(sort_attr, pymongo.ASCENDING) for sort_attr in sort_attrs])
    click.echo("Created")


def _drop(collection):  # pragma: no cover
    click.echo("Dropping...")
    collection.drop()
    click.echo("Dropped")


def _query(query, projection, collection):  # pragma: no cover
    docs = collection.find(query, projection=projection)
    for doc in docs:
        print(json.dumps(StorageFormat(doc).to_json_mapping(), indent=2))


def _status(collection):  # pragma: no cover
    click.echo(collection)
    click.echo("## Indexes ##")
    click.echo(pformat(collection.index_information()))
    click.echo("## Options ##")
    click.echo(pformat(collection.options()))
    click.echo("## Number of certs ##")
    click.echo(collection.estimated_document_count())
