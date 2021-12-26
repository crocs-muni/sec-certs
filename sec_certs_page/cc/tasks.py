import os
from collections import Counter
from datetime import datetime
from operator import itemgetter
from pathlib import Path
from shutil import rmtree

import sentry_sdk
from celery.utils.log import get_task_logger
from flask import current_app
from jsondiff import diff
from pkg_resources import get_distribution
from pymongo import DESCENDING
from sec_certs.dataset.common_criteria import CCDataset

from .. import celery, mongo
from ..utils import dictify_diff, dictify_serializable

logger = get_task_logger(__name__)


@celery.task(ignore_result=True)
def notify(run_id):
    # run = mongo.db.cc_log.find_one({"_id": run_id})
    # diffs = mongo.db.cc_diff.find({"run_id": run_id})
    pass


def process_new_certs(dset, new_ids, run_id, timestamp):
    with sentry_sdk.start_span(op="cc.db.new", description="Process new certs."):
        logger.info(f"Processing {len(new_ids)} new certificates.")
        for id in new_ids:
            # Add a cert to DB
            cert_data = dictify_serializable(dset[id], id_field="dgst")
            mongo.db.cc.insert_one(cert_data)
            mongo.db.cc_diff.insert_one(
                {
                    "run_id": run_id,
                    "dgst": id,
                    "timestamp": timestamp,
                    "type": "new",
                    "diff": cert_data,
                }
            )


def process_updated_certs(dset, updated_ids, run_id, timestamp):
    with sentry_sdk.start_span(op="cc.db.updated", description="Process updated certs."):
        logger.info(f"Processing {len(updated_ids)} updated certificates.")
        for id in updated_ids:
            # Process an updated cert, it can also be that a "removed" cert reappeared
            current_cert = mongo.db.cc.find_one({"_id": id})
            cert_data = dictify_serializable(dset[id], id_field="dgst")
            # Find the last diff
            last_diff = mongo.db.cc_diff.find_one({"dgst": id}, sort=[("timestamp", DESCENDING)])
            if cert_diff := diff(current_cert, cert_data, syntax="explicit"):
                # The cert changed, issue an update
                mongo.db.cc.replace_one({"_id": id}, cert_data)
                mongo.db.cc_diff.insert_one(
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
                mongo.db.cc_diff.insert_one(
                    {
                        "run_id": run_id,
                        "dgst": id,
                        "timestamp": timestamp,
                        "type": "back",
                    }
                )


def process_removed_certs(dset, removed_ids, run_id, timestamp):
    with sentry_sdk.start_span(op="cc.db.removed", description="Process removed certs."):
        logger.info(f"Processing {len(removed_ids)} removed certificates.")
        for id in removed_ids:
            # Find the last diff on this cert, if it is mark for removal, just continue
            last_diff = mongo.db.cc_diff.find_one({"dgst": id}, sort=[("timestamp", DESCENDING)])
            if last_diff and last_diff["type"] == "remove":
                continue
            # Mark the removal (but only once)
            mongo.db.cc_diff.insert_one(
                {
                    "run_id": run_id,
                    "dgst": id,
                    "timestamp": timestamp,
                    "type": "remove",
                }
            )


@celery.task(ignore_result=True)
def update_data():
    tool_version = get_distribution("sec-certs").version
    start = datetime.now()
    instance_path = Path(current_app.instance_path)
    cve_path = instance_path / current_app.config["DATASET_PATH_CVE"]
    cpe_path = instance_path / current_app.config["DATASET_PATH_CPE"]
    dset_path = instance_path / current_app.config["DATASET_PATH_CC"]
    output_path = instance_path / current_app.config["DATASET_PATH_CC_OUT"]

    dset = CCDataset({}, dset_path, "dataset", "Description")
    if not dset.auxillary_datasets_dir.exists():
        dset.auxillary_datasets_dir.mkdir(parents=True)
    if cve_path.exists():
        os.symlink(cve_path, dset.cve_dataset_path)
    if cpe_path.exists():
        os.symlink(cpe_path, dset.cpe_dataset_path)

    try:
        with sentry_sdk.start_span(op="cc.all", description="Get full CC dataset"):
            with sentry_sdk.start_span(op="cc.get_certs", description="Get certs from web"):
                dset.get_certs_from_web()
            with sentry_sdk.start_span(op="cc.download_pdfs", description="Download pdfs"):
                dset.download_all_pdfs()
            with sentry_sdk.start_span(op="cc.convert_pdfs", description="Convert pdfs"):
                dset.convert_all_pdfs()
            with sentry_sdk.start_span(op="cc.analyze", description="Analyze certificates"):
                dset.analyze_certificates()
            with sentry_sdk.start_span(op="cc.maintenance_updates", description="Process maintenance updates"):
                dset.process_maintenance_updates()
            dset.to_json(output_path)

        old_ids = set(map(itemgetter("_id"), mongo.db.cc.find({}, projection={"_id": 1})))
        current_ids = set(dset.certs.keys())

        new_ids = current_ids.difference(old_ids)
        removed_ids = old_ids.difference(current_ids)
        updated_ids = current_ids.intersection(old_ids)

        cert_states = Counter(key for cert in dset for key in cert.state.to_dict() if cert.state.to_dict()[key])

        end = datetime.now()
        update_result = mongo.db.cc_log.insert_one(
            {
                "start_time": start,
                "end_time": end,
                "tool_version": tool_version,
                "length": len(dset),
                "ok": True,
                "state": dset.state.to_dict(),
                "stats": {
                    "new_certs": len(new_ids),
                    "removed_ids": len(removed_ids),
                    "updated_ids": len(updated_ids),
                    "cert_states": dict(cert_states),
                },
            }
        )
        logger.info(f"Finished run {update_result.inserted_id}.")

        # TODO: Take dataset and certificate state into account when processing into DB.

        with sentry_sdk.start_span(op="cc.db", description="Process certs into DB."):
            process_new_certs(dset, new_ids, update_result.inserted_id, start)
            process_updated_certs(dset, updated_ids, update_result.inserted_id, start)
            process_removed_certs(dset, removed_ids, update_result.inserted_id, start)
        notify.delay(str(update_result.inserted_id))
    except Exception as e:
        end = datetime.now()
        mongo.db.cc_log.insert_one(
            {
                "start_time": start,
                "end_time": end,
                "tool_version": tool_version,
                "length": len(dset),
                "ok": False,
                "error": str(e),
                "state": dset.state.to_dict(),
            }
        )
        raise e
    finally:
        rmtree(dset_path, ignore_errors=True)
