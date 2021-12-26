"""Common Criteria commands."""

import json
from hashlib import blake2b

import click
from sec_certs.helpers import get_first_16_bytes_sha256, sanitize_link, sanitize_string
from tqdm import tqdm

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


@cc.cli.command("import-map", help="Import old CC dataset to create URL mapping.")
@click.argument("file", type=click.File())
def import_map(file):
    data = json.load(file)
    id_map = {}
    for key, cert in tqdm(data.items(), desc="Loading certs"):
        old_id = blake2b(key.encode(), digest_size=10).hexdigest()
        category = cert["csv_scan"]["cc_category"]
        name = sanitize_string(cert["csv_scan"]["cert_item_name"])
        link = sanitize_link(
            cert["csv_scan"]["link_cert_report"].replace("216.117.4.138:80", "www.commoncriteriaportal.org")
        )

        new_id = get_first_16_bytes_sha256(category + name + link)
        by_id = list(mongo.db.cc.find({"_id": new_id}))
        if not by_id:
            by_report_link = list(mongo.db.cc.find({"report_link": link}))
            if not by_report_link:
                print(f"Not Found {key}")
            elif len(by_report_link) != 1:
                print(f"by_report_link issue {key}")
            else:
                id_map[old_id] = by_report_link[0]["_id"]
        elif len(by_id) != 1:
            print(f"by_id issue {key}")
        else:
            id_map[old_id] = new_id

    for key, val in tqdm(id_map.items(), desc="Inserting map entries"):
        mongo.db.cc_old.replace_one({"_id": key}, {"_id": key, "hashid": val}, upsert=True)
