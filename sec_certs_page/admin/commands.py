import click
from flask.cli import AppGroup

from .. import app, mongo
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
    current = mongo.db.list_collection_names()
    collections = {
        "cc_log",
        "cc_diff",
        "cc_old",
        "fips_log",
        "fips_diff",
        "fips_old",
        "pp_log",
        "pp_diff",
        "users",
        "feedback",
        "subs",
        "cve",
        "cpe",
    }
    for collection in collections.difference(current):
        mongo.db.create_collection(collection)
        click.echo(f"Created collection {collection}.")
