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
from sec_certs.dataset.fips import FIPSDataset

from .. import celery, mongo
from ..utils import dictify_diff, dictify_serializable

logger = get_task_logger(__name__)


@celery.task(ignore_result=True)
def update_data():
    tool_version = get_distribution("sec-certs").version
    start = datetime.now()
    instance_path = Path(current_app.instance_path)
    cve_path = instance_path / current_app.config["DATASET_PATH_CVE"]
    cpe_path = instance_path / current_app.config["DATASET_PATH_CPE"]
    dset_path = instance_path / current_app.config["DATASET_PATH_FIPS"]
    output_path = instance_path / current_app.config["DATASET_PATH_FIPS_OUT"]
    dset = FIPSDataset({}, dset_path, "dataset", "Description")
    if not dset.auxillary_datasets_dir.exists():
        dset.auxillary_datasets_dir.mkdir(parents=True)
    if cve_path.exists():
        os.symlink(cve_path, dset.cve_dataset_path)
    if cpe_path.exists():
        os.symlink(cpe_path, dset.cpe_dataset_path)
    try:
        with sentry_sdk.start_span(op="fips.all", description="Get full FIPS dataset"):
            with sentry_sdk.start_span(op="fips.get_certs", description="Get certs from web"):
                dset.get_certs_from_web()
            with sentry_sdk.start_span(op="fips.convert_pdfs", description="Convert pdfs"):
                dset.convert_all_pdfs()
            with sentry_sdk.start_span(op="fips.scan_pdfs", description="Scan pdfs"):
                dset.pdf_scan()
            with sentry_sdk.start_span(op="fips.tables", description="Extract tables"):
                dset.extract_certs_from_tables(high_precision=True)
            with sentry_sdk.start_span(op="fips.finalize_results", description="Finalize results"):
                dset.finalize_results()
            dset.to_json(output_path)

        old_ids = set(map(itemgetter("_id"), mongo.db.fips.find({}, projection={"_id": 1})))
        current_ids = set(dset.certs.keys())

        new_ids = current_ids.difference(old_ids)
        removed_ids = old_ids.difference(current_ids)
        updated_ids = current_ids.intersection(old_ids)

        cert_states = Counter(key for cert in dset for key in cert.state.to_dict() if cert.state.to_dict()[key])

        end = datetime.now()
        update_result = mongo.db.fips_log.insert_one(
            {
                "start_time": start,
                "end_time": end,
                "tool_version": tool_version,
                "length": len(dset),
                "ok": True,
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

        with sentry_sdk.start_span(op="fips.db", description="Process certs into DB."):
            with sentry_sdk.start_span(op="fips.db.new", description="Process new certs."):
                logger.info(f"Processing {len(new_ids)} new certificates.")
                for id in new_ids:
                    # Add a cert to DB
                    cert_data = dictify_serializable(dset[id], id_field="dgst")
                    mongo.db.fips.insert_one(cert_data)
                    mongo.db.fips_diff.insert_one(
                        {
                            "run_id": update_result.inserted_id,
                            "dgst": id,
                            "timestamp": start,
                            "type": "new",
                            "diff": cert_data,
                        }
                    )
            with sentry_sdk.start_span(op="fips.db.updated", description="Process updated certs."):
                logger.info(f"Processing {len(updated_ids)} updated certificates.")
                for id in updated_ids:
                    # Process an updated cert, it can also be that a "removed" cert reappeared
                    current_cert = mongo.db.fips.find_one({"_id": id})
                    cert_data = dictify_serializable(dset[id], id_field="dgst")
                    # Find the last diff
                    last_diff = mongo.db.fips_diff.find_one({"dgst": id}, sort=[("timestamp", DESCENDING)])
                    if cert_diff := diff(current_cert, cert_data):
                        # The cert changed, issue an update
                        mongo.db.fips.replace_one({"_id": id}, cert_data)
                        mongo.db.fips_diff.insert_one(
                            {
                                "run_id": update_result.inserted_id,
                                "dgst": id,
                                "timestamp": start,
                                "type": "change",
                                "diff": dictify_diff(cert_diff),
                            }
                        )
                    elif last_diff and last_diff["type"] == "remove":
                        # The cert did not change but came back from being marked removed
                        mongo.db.fips_diff.insert_one(
                            {
                                "run_id": update_result.inserted_id,
                                "dgst": id,
                                "timestamp": start,
                                "type": "back",
                            }
                        )
            with sentry_sdk.start_span(op="fips.db.removed", description="Process removed certs."):
                logger.info(f"Processing {len(removed_ids)} removed certificates.")
                for id in removed_ids:
                    # Find the last diff on this cert, if it is mark for removal, just continue
                    last_diff = mongo.db.fips_diff.find_one({"dgst": id}, sort=[("timestamp", DESCENDING)])
                    if last_diff and last_diff["type"] == "remove":
                        continue
                    # Mark the removal (but only once)
                    mongo.db.fips_diff.insert_one(
                        {
                            "run_id": update_result.inserted_id,
                            "dgst": id,
                            "timestamp": start,
                            "type": "remove",
                        }
                    )
    except Exception as e:
        end = datetime.now()
        mongo.db.fips_log.insert_one(
            {
                "start_time": start,
                "end_time": end,
                "tool_version": tool_version,
                "length": len(dset),
                "ok": False,
                "error": str(e),
            }
        )
        raise e
    finally:
        rmtree(dset_path, ignore_errors=True)
