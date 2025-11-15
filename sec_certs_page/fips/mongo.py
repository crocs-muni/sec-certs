from .. import mongo
from ..common.mongo import create_collection, drop_collection, query_collection


def create():
    create_collection(
        "fips", ["web_data.module_name"], ["cert_id", "heuristics.related_cves._value", "heuristics.cpe_matches._value"]
    )


def drop():
    drop_collection(mongo.db.fips)


def query(query, projection):
    return query_collection(query, projection, mongo.db.fips)
