import click

from .user import User, hash_password
from .. import app, mongo


@app.cli.command("add-user", help="Add a user.")
@click.option("-u", "--username", required=True)
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True, required=True)
@click.option("-e", "--email", required=True)
@click.option("-r", "--role", multiple=True)
def add_user(username, password, email, role):
    if User.get(username):
        click.echo("User already exists.")
        return
    pwhash = hash_password(password)
    user = User(username, pwhash, email, role)
    res = mongo.db.users.insert_one(user.dict)
    click.echo(f"User added _id={res.inserted_id}")


@app.cli.command("del-user", help="Delete a user.")
@click.option("-u", "--username", required=True)
def del_user(username):
    user = User.get(username)
    if not user:
        click.echo("User does not exist,")
        return
    if click.confirm(f"Do you really want to delete user {username}?"):
        mongo.db.users.delete_one({"username": username})
        click.echo(f"User deleted")


@app.cli.command("list-users", help="List users.")
def list_users():
    for doc in mongo.db.users.find({}):
        print(doc)
