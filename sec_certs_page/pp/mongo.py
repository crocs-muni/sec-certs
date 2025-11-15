from .. import mongo
from ..common.mongo import create_collection, drop_collection, query_collection


def create():
    create_collection("pp", ["web_data.name"], [])


def drop():
    drop_collection(mongo.db.pp)


def query(query, projection):
    return query_collection(query, projection, mongo.db.pp)
