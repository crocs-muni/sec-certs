import gzip
import hashlib
import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from logging import Logger
from operator import itemgetter
from pathlib import Path

import sentry_sdk
from dramatiq import pipeline
from flask import current_app
from pymongo import ReplaceOne
from sec_certs.configuration import config
from sec_certs.dataset.cpe import CPEDataset
from sec_certs.dataset.cve import CVEDataset
from sec_certs.sample.cpe import CPE
from sec_certs.utils.nvd_dataset_builder import CpeMatchNvdDatasetBuilder, CpeNvdDatasetBuilder, CveNvdDatasetBuilder
from tantivy import Document

from .. import runtime_config
from ..common.objformats import ObjFormat
from ..common.tasks.utils import actor
from . import mongo
from .index import cpe_index, cve_index

logger: Logger = logging.getLogger(__name__)

CVE_REINDEX_CHUNK = 5000
CPE_REINDEX_CHUNK = 10000


def _index_hash(fields: dict) -> str:
    """Stable hash over the index-relevant fields of a document."""
    return hashlib.sha256(json.dumps(fields, sort_keys=True, default=str).encode()).hexdigest()


@actor("cve_update", "cve_update", "updates", timedelta(hours=2))
def update_cve_data() -> None:  # pragma: no cover
    if runtime_config["CVE_SKIP_UPDATE"]:
        logger.info("Skipping update due to config.")
        return
    instance_path = Path(current_app.instance_path)
    cve_path = instance_path / current_app.config["DATASET_PATH_CVE"]
    cve_compressed_path = instance_path / current_app.config["DATASET_PATH_CVE_COMPRESSED"]

    logger.info("Getting CVEs.")
    with sentry_sdk.start_span(op="cve.get", name="Get CVEs."):
        if cve_path.exists():
            cve_dset = CVEDataset.from_json(cve_path)
        else:
            cve_dset = CVEDataset(json_path=cve_path)
        with CveNvdDatasetBuilder(api_key=config.nvd_api_key) as builder:
            cve_dset = builder.build_dataset(cve_dset)
    logger.info(f"Got {len(cve_dset)} CVEs.")

    logger.info("Saving CVE dataset.")
    with sentry_sdk.start_span(op="cve.save", name="Save CVEs."):
        cve_dset.to_json(cve_path)
        cve_dset.to_json(cve_compressed_path, compress=True)

    logger.info("Inserting CVEs.")
    changed_ids: list[str] = []
    with sentry_sdk.start_span(op="cve.insert", name="Insert CVEs into DB."):
        old_hashes = {d["_id"]: d.get("_index_hash") for d in mongo.db.cve.find({}, ["_index_hash"])}
        old_ids = set(old_hashes)
        new_ids = set()
        cves = list(cve_dset)
        for i in range(0, len(cve_dset), 10000):
            chunk = []
            for cve in cves[i : i + 10000]:
                cve_data = ObjFormat(cve).to_raw_format().to_working_format().to_storage_format().get()
                cve_data["_id"] = cve.cve_id
                h = _index_hash(
                    {
                        "cvss": cve_data.get("cvss"),
                        "published_date": cve_data.get("published_date"),
                        "cwe_ids": cve_data.get("cwe_ids"),
                    }
                )
                cve_data["_index_hash"] = h
                if old_hashes.get(cve.cve_id) != h:
                    changed_ids.append(cve.cve_id)
                new_ids.add(cve.cve_id)
                chunk.append(ReplaceOne({"_id": cve.cve_id}, cve_data, upsert=True))
            res = mongo.db.cve.bulk_write(chunk, ordered=False)
            res_vals = ", ".join(f"{k} = {v}" for k, v in res.bulk_api_result.items() if k != "upserted")
            logger.info(f"Inserted chunk: {res_vals}")

    logger.info("Cleaning up old CVEs.")
    with sentry_sdk.start_span(op="cve.cleanup", name="Cleanup CVEs from DB."):
        removed_ids = list(old_ids - new_ids)
        res = mongo.db.cve.delete_many({"_id": {"$in": removed_ids}})
        logger.info(f"Cleaned up {res.deleted_count} CVEs.")

    logger.info(f"Reindexing {len(changed_ids)} changed and {len(removed_ids)} removed CVEs.")
    to_reindex = changed_ids + removed_ids
    for i in range(0, len(to_reindex), CVE_REINDEX_CHUNK):
        cve_reindex_collection.send(to_reindex[i : i + CVE_REINDEX_CHUNK])


@actor("cpe_update", "cpe_update", "updates", timedelta(hours=2))
def update_cpe_data() -> None:  # pragma: no cover
    if runtime_config["CPE_SKIP_UPDATE"]:
        logger.info("Skipping update due to config.")
        return
    instance_path = Path(current_app.instance_path)
    cpe_path = instance_path / current_app.config["DATASET_PATH_CPE"]
    cpe_compressed_path = instance_path / current_app.config["DATASET_PATH_CPE_COMPRESSED"]

    logger.info("Getting CPEs.")
    with sentry_sdk.start_span(op="cpe.get", name="Get CPEs."):
        if cpe_path.exists():
            cpe_dset = CPEDataset.from_json(cpe_path)
        else:
            cpe_dset = CPEDataset(json_path=cpe_path)

        with CpeNvdDatasetBuilder(api_key=config.nvd_api_key) as builder:
            cpe_dset = builder.build_dataset(cpe_dset)
    logger.info(f"Got {len(cpe_dset)} CPEs.")

    logger.info("Saving CPE dataset.")
    with sentry_sdk.start_span(op="cpe.save", name="Save CPEs."):
        cpe_dset.to_json(cpe_path)
        cpe_dset.to_json(cpe_compressed_path, compress=True)

    logger.info("Inserting CPEs.")
    changed_uris: list[str] = []
    with sentry_sdk.start_span(op="cpe.insert", name="Insert CPEs into DB."):
        old_hashes = {d["_id"]: d.get("_index_hash") for d in mongo.db.cpe.find({}, ["_index_hash"])}
        old_uris = set(old_hashes)
        new_uris = set()
        cpes = list(cpe_dset)
        for i in range(0, len(cpe_dset), 10000):
            chunk = []
            for cpe in cpes[i : i + 10000]:
                cpe_data = ObjFormat(cpe).to_raw_format().to_working_format().to_storage_format().get()
                cpe_data["_id"] = cpe.uri
                h = _index_hash(
                    {
                        "uri": cpe_data.get("uri"),
                        "title": cpe_data.get("title"),
                        "cpe_id": cpe_data.get("cpe_id"),
                    }
                )
                cpe_data["_index_hash"] = h
                if old_hashes.get(cpe.uri) != h:
                    changed_uris.append(cpe.uri)
                new_uris.add(cpe.uri)
                chunk.append(ReplaceOne({"_id": cpe.uri}, cpe_data, upsert=True))
            res = mongo.db.cpe.bulk_write(chunk, ordered=False)
            res_vals = ", ".join(f"{k} = {v}" for k, v in res.bulk_api_result.items() if k != "upserted")
            logger.info(f"Inserted chunk: {res_vals}")

    logger.info("Cleaning up old CPEs.")
    with sentry_sdk.start_span(op="cpe.cleanup", name="Cleanup CPEs from DB."):
        removed_uris = list(old_uris - new_uris)
        res = mongo.db.cpe.delete_many({"_id": {"$in": removed_uris}})
        logger.info(f"Cleaned up {res.deleted_count} CPEs.")

    logger.info(f"Reindexing {len(changed_uris)} changed and {len(removed_uris)} removed CPEs.")
    to_reindex = changed_uris + removed_uris
    for i in range(0, len(to_reindex), CPE_REINDEX_CHUNK):
        cpe_reindex_collection.send(to_reindex[i : i + CPE_REINDEX_CHUNK])


@actor("cpe_match_update", "cpe_match_update", "updates", timedelta(hours=2))
def update_cpe_match_data() -> None:  # pragma: no cover
    if runtime_config["CPE_MATCH_SKIP_UPDATE"]:
        logger.info("Skipping update due to config.")
        return
    instance_path = Path(current_app.instance_path)
    match_path = instance_path / current_app.config["DATASET_PATH_CPE_MATCH"]
    match_compressed_path = instance_path / current_app.config["DATASET_PATH_CPE_MATCH_COMPRESSED"]

    logger.info("Getting CPE matches.")
    with sentry_sdk.start_span(op="cpe_match.get", name="Get CPE matches."):
        if match_path.exists():
            with match_path.open("r", encoding="utf-8") as handle:
                match_dset = json.load(handle)
        else:
            match_dset = None

        with CpeMatchNvdDatasetBuilder(api_key=config.nvd_api_key) as builder:
            match_dset = builder.build_dataset(match_dset)

    logger.info("Saving CPE match dataset.")
    with sentry_sdk.start_span(op="cpe_match.save", name="Save CPE matches."):
        with match_path.open("wt", encoding="UTF-8") as handle:
            json.dump(match_dset, handle, indent=4)
        with gzip.open(match_compressed_path, "wt", encoding="UTF-8") as gzip_handle:
            json.dump(match_dset, gzip_handle, indent=4)  # type: ignore

    logger.info("Inserting CPE matches.")
    with sentry_sdk.start_span(op="cpe_match.insert", name="Insert CPE matches into DB."):
        old_ids = set(map(itemgetter("_id"), mongo.db.cpe_match.find({}, ["_id"])))
        new_ids = set()
        match_keys = list(match_dset["match_strings"].keys())
        for i in range(0, len(match_keys), 10000):
            chunk = []
            for key in match_keys[i : i + 10000]:
                match_data = match_dset["match_strings"][key].copy()
                match_data["_id"] = key
                new_ids.add(key)
                chunk.append(ReplaceOne({"_id": key}, match_data, upsert=True))
            res = mongo.db.cpe_match.bulk_write(chunk, ordered=False)
            res_vals = ", ".join(f"{k} = {v}" for k, v in res.bulk_api_result.items() if k != "upserted")
            logger.info(f"Inserted chunk: {res_vals}")

    logger.info("Cleaning up old CPE matches.")
    with sentry_sdk.start_span(op="cpe_match.cleanup", name="Cleanup CPE matches from DB."):
        res = mongo.db.cpe_match.delete_many({"_id": {"$in": list(old_ids - new_ids)}})
        logger.info(f"Cleaned up {res.deleted_count} CPE matches.")


def _aggregate_cert_counts(path: str, ids: list) -> dict[str, int]:
    """Count CC + FIPS certificates linked to each of ``ids`` (CVE id / CPE uri) via ``path``."""
    counts: dict[str, int] = defaultdict(int)
    agg = [
        {"$match": {path: {"$in": ids}}},
        {"$unwind": f"${path}"},
        {"$match": {path: {"$in": ids}}},
        {"$group": {"_id": f"${path}", "n": {"$sum": 1}}},
    ]
    for coll in ("cc", "fips"):
        for row in mongo.db[coll].aggregate(agg):
            counts[row["_id"]] += row["n"]
    return counts


class VulnIndexer:  # pragma: no cover
    """
    Reindex Tantivy documents for a vulnerability collection straight from MongoDB.

    Unlike the certificate ``Indexer``, there are no per-document text files on disk, so
    ``reindex`` streams the Mongo docs directly. Passing an id that no longer exists in Mongo
    simply leaves it deleted from the index (used to drop removed CVEs/CPEs).
    """

    collection: str
    count_path: str
    index: object

    def create_document(self, doc: dict, cert_count: int) -> Document:
        raise NotImplementedError

    def reindex(self, ids):
        ids = list(ids)
        logger.info(f"Reindexing {len(ids)} {self.collection} documents.")
        counts = _aggregate_cert_counts(self.count_path, ids)
        writer = self.index.writer()
        for _id in ids:
            writer.delete_documents_by_term("id", _id)
        found = {d["_id"]: d for d in mongo.db[self.collection].find({"_id": {"$in": ids}})}
        updated = 0
        for _id in ids:
            doc = found.get(_id)
            if doc is None:
                continue
            writer.add_document(self.create_document(doc, counts.get(_id, 0)))
            updated += 1
        writer.commit()
        writer.wait_merging_threads()
        self.index.reload()
        logger.info(f"Reindexed {updated} {self.collection} documents ({len(ids) - updated} removed).")


class CVEIndexer(VulnIndexer):  # pragma: no cover
    collection = "cve"
    count_path = "heuristics.related_cves._value"

    def __init__(self):
        self.index = cve_index()

    def create_document(self, cve, cert_count):
        doc = Document()
        cve_id = cve["_id"]
        doc.add_text("id", cve_id)
        doc.add_text("cve_id", cve_id)
        doc.add_text("cve_id_tokenized", cve_id)
        _, year, seq = cve_id.split("-", 2)
        doc.add_integer("cve_number", int(year) * 10_000_000 + int(seq))
        cvss = cve.get("cvss") or {}
        doc.add_text("severity", cvss.get("severity"))
        base_score = cvss.get("base_score")
        doc.add_float("base_score", float(base_score))
        published = cve.get("published_date")
        if published:
            doc.add_date("published_date", datetime.fromisoformat(published))
        cwe = cve.get("cwe_ids")
        if cwe:
            for entry in cwe.get("_value") or []:
                doc.add_text("cwe", entry)
                doc.add_text("cwe_tokenized", entry)
        doc.add_integer("cert_count", cert_count)
        return doc


class CPEIndexer(VulnIndexer):  # pragma: no cover
    collection = "cpe"
    count_path = "heuristics.cpe_matches._value"

    def __init__(self):
        self.index = cpe_index()

    def create_document(self, cpe_doc, cert_count):
        uri = cpe_doc["uri"]
        # vendor / item_name / version are derived from the uri (not stored on the doc).
        cpe = CPE(cpe_doc["cpe_id"], uri, cpe_doc.get("title"))
        doc = Document()
        doc.add_text("id", uri)
        doc.add_text("uri", uri)
        doc.add_text("uri_tokenized", uri)
        doc.add_text("vendor", cpe.vendor)
        doc.add_text("product", cpe.item_name)
        if cpe.title:
            doc.add_text("cpe_title", cpe.title)
        doc.add_text("version", cpe.version)
        doc.add_integer("cert_count", cert_count)
        return doc


@actor("cve_reindex_collection", "cve_reindex_collection", "updates", timedelta(hours=4))
def cve_reindex_collection(ids):  # pragma: no cover
    CVEIndexer().reindex(ids)


@actor("cve_reindex_all", "cve_reindex_all", "updates", timedelta(hours=2))
def cve_reindex_all():  # pragma: no cover
    ids = [doc["_id"] for doc in mongo.db.cve.find({}, {"_id": 1})]
    tasks = [
        cve_reindex_collection.message_with_options(args=(ids[i : i + CVE_REINDEX_CHUNK],), pipe_ignore=True)
        for i in range(0, len(ids), CVE_REINDEX_CHUNK)
    ]
    if tasks:
        pipeline(tasks).run()


@actor("cpe_reindex_collection", "cpe_reindex_collection", "updates", timedelta(hours=4))
def cpe_reindex_collection(ids):  # pragma: no cover
    CPEIndexer().reindex(ids)


@actor("cpe_reindex_all", "cpe_reindex_all", "updates", timedelta(hours=2))
def cpe_reindex_all():  # pragma: no cover
    ids = [doc["_id"] for doc in mongo.db.cpe.find({}, {"_id": 1})]
    tasks = [
        cpe_reindex_collection.message_with_options(args=(ids[i : i + CPE_REINDEX_CHUNK],), pipe_ignore=True)
        for i in range(0, len(ids), CPE_REINDEX_CHUNK)
    ]
    if tasks:
        pipeline(tasks).run()
