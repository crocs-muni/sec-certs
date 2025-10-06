"""FIPS commands."""

import json
from datetime import datetime
from glob import glob
from hashlib import blake2b
from pathlib import Path

import click
from sec_certs.sample.fips_iut import IUTSnapshot
from sec_certs.sample.fips_mip import MIPSnapshot
from tqdm import tqdm

from .. import mongo
from ..common.mongo import collection_status, create_collection, drop_collection, query_collection
from ..common.objformats import ObjFormat
from . import fips
from .tasks import update_kb as update_kb_core


@fips.cli.command("create", help="Create the DB of FIPS 140 certs.")
def create():  # pragma: no cover
    create_collection(
        "fips", ["web_data.module_name"], ["cert_id", "heuristics.related_cves._value", "heuristics.cpe_matches._value"]
    )


@fips.cli.command("drop", help="Drop the DB of FIPS 140 certs.")
def drop():  # pragma: no cover
    drop_collection(mongo.db.fips)


@fips.cli.command("query", help="Query the MongoDB for certs.")
@click.option("-p", "--projection", type=json.loads, help="Projection to use with the query.")
@click.argument("query", type=json.loads)
def query(query, projection):  # pragma: no cover
    docs = query_collection(query, projection, mongo.db.fips)
    for doc in docs:
        print(json.dumps(doc, indent=2))


@fips.cli.command("status", help="Print status information for the MongoDB collection.")
def status():  # pragma: no cover
    collection_status(mongo.db.fips)


@fips.cli.command("import-map", help="Import old FIPS dataset to create URL mapping.")
def import_map():  # pragma: no cover
    for cert in tqdm(list(mongo.db.fips.find({}, {"cert_id": True})), desc="Processing certs"):
        old_id = blake2b(str(cert["cert_id"]).encode(), digest_size=10).hexdigest()
        new_id = cert["_id"]
        mongo.db.fips_old.replace_one({"_id": old_id}, {"_id": old_id, "hashid": new_id}, upsert=True)


@fips.cli.command("import-iut", help="Import manually downloaded FIPS IUT pages.")
@click.argument("directory", type=click.types.Path(exists=True, file_okay=False, dir_okay=True))
def import_iut(directory):  # pragma: no cover
    already_present = list(
        map(
            lambda entry: datetime.fromisoformat(entry["timestamp"]).date(),
            mongo.db.fips_iut.find({}, {"timestamp": 1}),
        )
    )

    directory = Path(directory)
    for iut_fname in sorted(glob(str(directory / "fips_iut_*.html"))):
        try:
            iut_snapshot = IUTSnapshot.from_dump(iut_fname)
        except Exception as e:
            click.echo(f"Not importing {iut_fname} due to '{e}'.")
            continue
        if iut_snapshot.timestamp.date() in already_present:
            click.echo(f"Skipping {iut_fname} due to snapshot on date already present.")
            continue
        snap_data = ObjFormat(iut_snapshot).to_raw_format().to_working_format().to_storage_format().get()
        mongo.db.fips_iut.insert_one(snap_data)
        click.echo(f"Imported {iut_fname}")


@fips.cli.command("import-mip", help="Import manually downloaded FIPS MIP pages.")
@click.argument("directory", type=click.types.Path(exists=True, file_okay=False, dir_okay=True))
def import_mip(directory):  # pragma: no cover
    already_present = list(
        map(
            lambda entry: datetime.fromisoformat(entry["timestamp"]).date(),
            mongo.db.fips_mip.find({}, {"timestamp": 1}),
        )
    )

    directory = Path(directory)
    for mip_fname in sorted(glob(str(directory / "fips_mip_*.html"))):
        try:
            mip_snapshot = MIPSnapshot.from_dump(mip_fname)
        except Exception as e:
            click.echo(f"Not importing {mip_fname} due to '{e}'.")
            continue
        if mip_snapshot.timestamp.date() in already_present:
            click.echo(f"Skipping {mip_fname} due to snapshot on date already present.")
            continue
        snap_data = ObjFormat(mip_snapshot).to_raw_format().to_working_format().to_storage_format().get()
        mongo.db.fips_mip.insert_one(snap_data)
        click.echo(f"Imported {mip_fname}")


@fips.cli.command("update-kb", help="Update the KB of FIPS certs.")
def update_kb():
    ids = list(map(lambda doc: doc["_id"], mongo.db.fips.find({}, {"_id": 1})))
    targets = [(dgst, "target", None) for dgst in ids]
    update_kb_core(targets)
