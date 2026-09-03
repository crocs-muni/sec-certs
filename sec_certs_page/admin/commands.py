import click
from flask.cli import AppGroup
from pymongo import UpdateOne
from tqdm import tqdm

from .. import app, mongo
from ..cc.tasks import reindex_collection as reindex_cc
from ..common.mongo import init_collections as init_collections_func
from ..eucc.tasks import reindex_collection as reindex_eucc
from ..fips.tasks import reindex_collection as reindex_fips
from ..pp.tasks import reindex_collection as reindex_pp
from ..user.models import User, hash_password
from ..vuln.tasks import cpe_reindex_collection, cve_reindex_collection

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


@app.cli.command("index-collections", help="Index the CC, FIPS, EUCC, PP, CVE and CPE collections into Tantivy.")
def index_collections():  # pragma: no cover
    for name, collection, reindex in (
        ("CC", mongo.db.cc, reindex_cc),
        ("FIPS", mongo.db.fips, reindex_fips),
        ("EUCC", mongo.db.eucc, reindex_eucc),
        ("PP", mongo.db.pp, reindex_pp),
        ("CVE", mongo.db.cve, cve_reindex_collection),
        ("CPE", mongo.db.cpe, cpe_reindex_collection),
    ):
        click.echo(f"Building {name} entries to index...")
        entries = [doc["_id"] for doc in tqdm(collection.find({}, {"_id": 1}))]
        click.echo(f"Indexing {name} entries...")
        reindex(entries)


DIFF_TYPE_STATS = {
    "change": "changed_ids",
    "remove": "current_removed_ids",
    "back": "back_ids",
}


@app.cli.command("backfill-update-stats", help="Recount the per-type diff counts on past update runs.")
@click.option(
    "-s",
    "--scheme",
    "schemes",
    multiple=True,
    type=click.Choice(("cc", "fips", "pp", "eucc")),
    help="Scheme to process, repeatable. Defaults to all of them.",
)
@click.option("--dry-run", is_flag=True, help="Report what would change without writing.")
def backfill_update_stats(schemes, dry_run):  # pragma: no cover
    for scheme in schemes or ("cc", "fips", "pp", "eucc"):
        diffs = mongo.db[f"{scheme}_diff"]
        logs = mongo.db[f"{scheme}_log"]
        counted: dict = {}
        for group in diffs.aggregate([{"$group": {"_id": {"run": "$run_id", "type": "$type"}, "n": {"$sum": 1}}}]):
            counted.setdefault(group["_id"]["run"], {})[group["_id"]["type"]] = group["n"]

        requests = []
        for run in logs.find({}, {"stats": 1}):
            per_type = counted.get(run["_id"], {})
            stats = run.get("stats", {})
            update = {
                f"stats.{key}": per_type.get(diff_type, 0)
                for diff_type, key in DIFF_TYPE_STATS.items()
                if stats.get(key) != per_type.get(diff_type, 0)
            }
            if update:
                requests.append(UpdateOne({"_id": run["_id"]}, {"$set": update}))

        total = logs.count_documents({})
        if not requests:
            click.echo(f"{scheme}: {total} runs, all counts already correct.")
            continue
        if dry_run:
            click.echo(f"{scheme}: would update {len(requests)} of {total} runs.")
            continue
        result = logs.bulk_write(requests, ordered=False)
        click.echo(f"{scheme}: updated {result.modified_count} of {total} runs.")
