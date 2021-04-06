import json
import html
import codecs
from datetime import datetime

import click

from .. import mongo
from . import cc
from ..commands import _add, _update, _create, _drop, _query


def cc_mapper(cert):
    if "csv_scan" in cert:
        cs = cert["csv_scan"]
        if "cc_archived_date" in cs:
            cs["cc_archived_date"] = datetime.strptime(cs["cc_archived_date"], "%m/%d/%Y") if cs["cc_archived_date"] else None
        if "cc_certification_date" in cs:
            cs["cc_certification_date"] = datetime.strptime(cs["cc_certification_date"], "%m/%d/%Y") if cs["cc_certification_date"] else None
        if "cert_item_name" in cs:
            cs["cert_item_name"] = html.unescape(cs["cert_item_name"])
    if "frontpage_scan" in cert:
        fs = cert["frontpage_scan"]
        for n in ("cc_security_level", "cc_version", "cert_item", "cert_lab", "developer"):
            if n in fs:
                fs[n] = codecs.decode(fs[n], "unicode-escape")
    return cert


@cc.cli.command("import", help="Import CC certs.")
@click.argument("file", type=click.File())
def add(file):
    _add(file, mongo.db.cc, None, cc_mapper)


@cc.cli.command("update", help="Update CC certs.")
@click.option(
    "-r", "--remove", is_flag=True, help="Remove certs not present in the update file."
)
@click.argument("file", type=click.File())
def update(file, remove):
    _update(file, remove, mongo.db.cc, None, cc_mapper)


@cc.cli.command("create", help="Create the DB of CC certs.")
def create():
    _create("cc", "csv_scan.cert_item_name")


@cc.cli.command("drop", help="Drop the DB of CC certs.")
def drop():
    _drop(mongo.db.cc)


@cc.cli.command("query", help="Query the MongoDB for certs.")
@click.option("-p", "--projection", type=json.loads, help="Projection to use with the query.")
@click.argument("query", type=json.loads)
def query(query, projection):
    _query(query, projection, mongo.db.cc)
