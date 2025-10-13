import click
import pymongo
from flask.cli import AppGroup
from tqdm import tqdm

from .. import app, mongo
from ..cc.tasks import reindex_collection as reindex_cc
from ..common.mongo import init_collections as init_collections_func
from ..fips.tasks import reindex_collection as reindex_fips
from .user import User, hash_password

user_group = AppGroup("user", help="Manage users.")
app.cli.add_command(user_group)


@user_group.command("add", help="Add a user.")
@click.option("-u", "--username", required=True)
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True, required=True)
@click.option("-e", "--email", required=True)
@click.option("-r", "--role", multiple=True)
def add_user(username, password, email, role):  # pragma: no cover
    if User.get(username):
        click.echo("User already exists.")
        return
    pwhash = hash_password(password)
    user = User(username, pwhash, email, role)
    res = mongo.db.users.insert_one(user.dict)
    click.echo(f"User added _id={res.inserted_id}")


@user_group.command("del", help="Delete a user.")
@click.option("-u", "--username", required=True)
def del_user(username):  # pragma: no cover
    user = User.get(username)
    if not user:
        click.echo("User does not exist,")
        return
    if click.confirm(f"Do you really want to delete user {username}?"):
        mongo.db.users.delete_one({"username": username})
        click.echo("User deleted")


@user_group.command("list", help="List users.")
def list_users():  # pragma: no cover
    for doc in mongo.db.users.find({}):
        print(doc)


@app.cli.command("init-collections", help="Initialize the miscellaneous collections.")
def init_collections():  # pragma: no cover
    click.echo("Remember that CC, FIPS and PP base collections are created through different commands.")
    created, existed = init_collections_func()
    if created:
        click.echo(f"Created collections: {', '.join(created)}")
    if existed:
        click.echo(f"Collections already present: {', '.join(existed)}")


@app.cli.command("index-collections", help="Index the CC and FIPS collections with whoosh")
def index_collections():  # pragma: no cover
    click.echo("Building CC entries to index...")
    cc_entries = []
    for id in tqdm(mongo.db.cc.find({}, {"_id": 1})):
        cc_entries.append((id["_id"], "report"))
        cc_entries.append((id["_id"], "target"))
    click.echo("Indexing CC entries...")
    reindex_cc(cc_entries)

    click.echo("Building FIPS entries to index...")
    fips_entries = [(id["_id"], "target") for id in tqdm(mongo.db.fips.find({}, {"_id": 1}))]
    click.echo("Indexing FIPS entries...")
    reindex_fips(fips_entries)
