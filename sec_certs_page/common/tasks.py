from itertools import product
from pathlib import Path

import sentry_sdk
from celery.utils.log import get_task_logger
from flask import current_app
from jsondiff import diff
from pymongo import DESCENDING

from sec_certs_page import mongo
from sec_certs_page.utils import dictify_diff, dictify_serializable

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
            cert_data = dictify_serializable(dset[id], id_field="dgst")
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
            current_cert = mongo.db[collection].find_one({"_id": id})
            cert_data = dictify_serializable(dset[id], id_field="dgst")
            # Find the last diff
            last_diff = mongo.db[diff_collection].find_one({"dgst": id}, sort=[("timestamp", DESCENDING)])
            if cert_diff := diff(current_cert, cert_data, syntax="explicit"):
                # The cert changed, issue an update
                mongo.db[collection].replace_one({"_id": id}, cert_data)
                mongo.db[diff_collection].insert_one(
                    {
                        "run_id": run_id,
                        "dgst": id,
                        "timestamp": timestamp,
                        "type": "change",
                        "diff": dictify_diff(cert_diff),
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
