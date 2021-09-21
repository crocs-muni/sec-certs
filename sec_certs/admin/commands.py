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
    id = mongo.db.users.insert_one(user.dict)
    click.echo(f"User added _id={id}")
