from pprint import pformat

import pymongo

from .. import mongo
from .objformats import StorageFormat


def init_collections():
    """Initialize the miscellaneous collections."""
    current = mongo.db.list_collection_names()
    collections = {
        "cc_log",
        "cc_diff",
        "cc_old",
        "cc_scheme",
        "fips_log",
        "fips_diff",
        "fips_old",
        "fips_mip",
        "fips_iut",
        "pp_log",
        "pp_diff",
        "users",
        "email_tokens",
        "accounting",
        "subs",
        "cve",
        "cpe",
        "cpe_match",
    }
    to_create = collections.difference(current)
    for collection in to_create:
        mongo.db.create_collection(collection)
        if collection == "cve":
            mongo.db[collection].create_index([("vulnerable_cpes.criteria_id", pymongo.ASCENDING)])
            mongo.db[collection].create_index(
                [("vulnerable_criteria_configurations.components.0.criteria_id", pymongo.ASCENDING)]
            )
        if collection == "cpe_match":
            mongo.db[collection].create_index([("matches.cpeName", pymongo.ASCENDING)])
        if collection in ("cc_diff", "fips_diff"):
            mongo.db[collection].create_index([("dgst", pymongo.ASCENDING)])
    return to_create, current


def create_collection(collection_name, text_attrs, sort_attrs):
    """Create a MongoDB collection with specified text and sort indexes."""
    res = mongo.db.create_collection(collection_name)
    if text_attrs:
        mongo.db[collection_name].create_index([(text_attr, pymongo.TEXT) for text_attr in text_attrs])
    if sort_attrs:
        mongo.db[collection_name].create_index([(sort_attr, pymongo.ASCENDING) for sort_attr in sort_attrs])
    return res


def drop_collection(collection):
    """Drop a MongoDB collection."""
    collection.drop()


def query_collection(query, projection, collection):
    """Query a MongoDB collection and return the results as JSON mappings."""
    docs = collection.find(query, projection=projection)
    return list(map(lambda d: StorageFormat(d).to_json_mapping(), docs))


def collection_status(collection):
    print(collection)
    print("## Indexes ##")
    print(pformat(collection.index_information()))
    print("## Options ##")
    print(pformat(collection.options()))
    print("## Number of certs ##")
    print(collection.estimated_document_count())
