from itertools import product
from pathlib import Path

import sentry_sdk
from celery.utils.log import get_task_logger
from flask import current_app
from jsondiff import diff
from pymongo import DESCENDING

from .. import mongo
from .objformats import ObjFormat, StorageFormat, WorkingFormat

logger = get_task_logger(__name__)


def make_dataset_paths(collection):
    instance_path = Path(current_app.instance_path)
    ns = current_app.config.get_namespace("DATASET_PATH_")

    res = {
        "cve_path": instance_path / ns["cve"],
        "cpe_path": instance_path / ns["cpe"],
        "dset_path": instance_path / ns[collection],
        "output_path": instance_path / ns[f"{collection}_out"],
        "dir_path": instance_path / ns[f"{collection}_dir"],
    }

    for document, format in product(("report", "target"), ("pdf", "txt")):
        path = res["dir_path"] / document / format
        path.mkdir(parents=True, exist_ok=True)
        res[f"{document}_{format}"] = path

    return res


def process_new_certs(collection, diff_collection, dset, new_ids, run_id, timestamp):  # pragma: no cover
    with sentry_sdk.start_span(op=f"{collection}.db.new", description="Process new certs."):
        logger.info(f"Processing {len(new_ids)} new certificates.")
        for id in new_ids:
            # Add a cert to DB
            cert_data = ObjFormat(dset[id]).to_raw_format().to_working_format().to_storage_format().get()
            cert_data["_id"] = cert_data["dgst"]
            mongo.db[collection].insert_one(cert_data)
            mongo.db[diff_collection].insert_one(
                {
                    "run_id": run_id,
                    "dgst": id,
                    "timestamp": timestamp,
                    "type": "new",
                    "diff": cert_data,
                }
            )


def process_updated_certs(collection, diff_collection, dset, updated_ids, run_id, timestamp):  # pragma: no cover
    with sentry_sdk.start_span(op=f"{collection}.db.updated", description="Process updated certs."):
        logger.info(f"Processing {len(updated_ids)} updated certificates.")
        for id in updated_ids:
            # Process an updated cert, it can also be that a "removed" cert reappeared
            working_current_cert = StorageFormat(mongo.db[collection].find_one({"_id": id})).to_working_format().get()
            working_cert = ObjFormat(dset[id]).to_raw_format().to_working_format()
            working_cert_data = working_cert.get()
            working_cert_data["_id"] = id
            # Find the last diff
            last_diff = mongo.db[diff_collection].find_one({"dgst": id}, sort=[("timestamp", DESCENDING)])
            if cert_diff := diff(working_current_cert, working_cert_data, syntax="explicit"):
                working_diff = WorkingFormat(cert_diff)
                storage_cert = working_cert.to_storage_format().get()
                storage_cert["_id"] = id
                # The cert changed, issue an update
                mongo.db[collection].replace_one({"_id": id}, storage_cert)
                mongo.db[diff_collection].insert_one(
                    {
                        "run_id": run_id,
                        "dgst": id,
                        "timestamp": timestamp,
                        "type": "change",
                        "diff": working_diff.to_storage_format().get(),
                    }
                )
            elif last_diff and last_diff["type"] == "remove":
                # The cert did not change but came back from being marked removed
                mongo.db[diff_collection].insert_one(
                    {
                        "run_id": run_id,
                        "dgst": id,
                        "timestamp": timestamp,
                        "type": "back",
                    }
                )


def process_removed_certs(collection, diff_collection, dset, removed_ids, run_id, timestamp):  # pragma: no cover
    with sentry_sdk.start_span(op=f"{collection}.db.removed", description="Process removed certs."):
        logger.info(f"Processing {len(removed_ids)} removed certificates.")
        for id in removed_ids:
            # Find the last diff on this cert, if it is mark for removal, just continue
            last_diff = mongo.db[diff_collection].find_one({"dgst": id}, sort=[("timestamp", DESCENDING)])
            if last_diff and last_diff["type"] == "remove":
                continue
            # Mark the removal (but only once)
            mongo.db[diff_collection].insert_one(
                {
                    "run_id": run_id,
                    "dgst": id,
                    "timestamp": timestamp,
                    "type": "remove",
                }
            )
