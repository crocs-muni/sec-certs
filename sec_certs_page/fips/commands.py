"""FIPS commands."""

from datetime import datetime
import json

import click

from .. import mongo
from ..commands import _add, _create, _drop, _query, _update
from . import fips


def fips_mapper(cert):
    if "web_scan" in cert:
        ws = cert["web_scan"]
        if "date_validation" in ws:
            ws["date_validation"] = list(map(lambda date: datetime.strptime(date, "%Y-%m-%d 00:00:00"), ws["date_validation"]))
        if "date_sunset" in ws and ws["date_sunset"]:
            ws["date_sunset"] = datetime.strptime(ws["date_sunset"], "%Y-%m-%d 00:00:00")
    if "cert_id" in cert:
        cert["cert_id"] = int(cert["cert_id"])
    return cert


@fips.cli.command("import", help="Import FIPS 140 certs.")
@click.argument("file", type=click.File())
def add(file):
    _add(file, mongo.db.fips, ("certs",), fips_mapper)


@fips.cli.command("update", help="Update FIPS 140 certs.")
@click.option(
    "-r", "--remove", is_flag=True, help="Remove certs not present in the update file."
)
@click.argument("file", type=click.File())
def update(file, remove):
    _update(file, remove, mongo.db.fips, ("certs",), fips_mapper)


@fips.cli.command("create", help="Create the DB of FIPS 140 certs.")
def create():
    _create("fips", ["web_scan.module_name"], [])


@fips.cli.command("drop", help="Drop the DB of FIPS 140 certs.")
def drop():
    _drop(mongo.db.fips)


@fips.cli.command("query", help="Query the MongoDB for certs.")
@click.option("-p", "--projection", type=json.loads, help="Projection to use with the query.")
@click.argument("query", type=json.loads)
def query(query, projection):
    _query(query, projection, mongo.db.fips)
