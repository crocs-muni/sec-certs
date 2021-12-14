from datetime import datetime
from operator import itemgetter
from pathlib import Path
from pkg_resources import get_distribution

import sentry_sdk

from celery.utils.log import get_task_logger
from flask import current_app
from shutil import rmtree
from jsondiff import diff
from pymongo import DESCENDING
from sec_certs.dataset.common_criteria import CCDataset

from .. import celery, mongo
from ..utils import remove_dots


logging = get_task_logger(__name__)


@celery.task(ignore_result=True)
def update_data():
    tool_version = get_distribution("sec-certs").version
    start = datetime.now()
    instance_path = Path(current_app.instance_path)
    dset_path = instance_path / current_app.config["DATASET_PATH_CC"]
    output_path = instance_path / current_app.config["DATASET_PATH_CC_OUT"]
    dset = CCDataset({}, dset_path, "dataset", "Description")
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
            end = datetime.now()
            update_result = mongo.db.cc_log.insert_one({
                "start_time": start,
                "end_time": end,
                "tool_version": tool_version,
                "length": len(dset),
                "ok": True
            })

            old_ids = set(map(itemgetter("_id"), mongo.db.cc.find({}, projection={"_id": 1})))
            current_ids = set(dset.certs.keys())

            new_ids = current_ids.difference(old_ids)
            removed_ids = old_ids.difference(current_ids)
            updated_ids = current_ids.intersection(old_ids)

            # TODO: Take dataset and certificate state into account when processing into DB.

            with sentry_sdk.start_span(op="cc.db", description="Process certs into DB."):
                with sentry_sdk.start_span(op="cc.db.new", description="Process new certs."):
                    for id in new_ids:
                        # Add a cert to DB
                        cert = dset[id]
                        cert_data = cert.to_dict()
                        cert_data["_id"] = cert_data["dgst"]
                        cert_data = remove_dots(cert_data)
                        mongo.db.cc.insert_one(cert_data)
                        mongo.db.cc_diff.insert_one({
                            "run_id": update_result.inserted_id,
                            "dgst": id,
                            "timestamp": start,
                            "type": "new",
                            "diff": cert_data
                        })
                with sentry_sdk.start_span(op="cc.db.updated", description="Process updated certs."):
                    for id in updated_ids:
                        # Process an updated cert, it can also be that a "removed" cert reappeared
                        current_cert = mongo.db.cc.find_one({"_id": id})
                        cert = dset[id]
                        cert_data = cert.to_dict()
                        cert_data["_id"] = cert_data["dgst"]
                        cert_data = remove_dots(cert_data)
                        # Find the last diff
                        last_diff = mongo.db.cc_diff.find_one({"dgst": id}, sort=("timestamp", DESCENDING))
                        if cert_diff := diff(current_cert, cert_data):
                            # The cert changed, issue an update
                            mongo.db.cc.replace_one({"_id": id}, cert_data)
                            mongo.db.cc_diff.insert_one({
                                "run_id": update_result.inserted_id,
                                "dgst": id,
                                "timestamp": start,
                                "type": "change",
                                "diff": cert_diff
                            })
                        elif last_diff and last_diff["type"] == "remove":
                            # The cert did not change but came back from being marked removed
                            mongo.db.cc_diff.insert_one({
                                "run_id": update_result.inserted_id,
                                "dgst": id,
                                "timestamp": start,
                                "type": "back"
                            })
                with sentry_sdk.start_span(op="cc.db.removed", description="Process removed certs."):
                    for id in removed_ids:
                        # Find the last diff on this cert, if it is mark for removal, just continue
                        last_diff = mongo.db.cc_diff.find_one({"dgst": id}, sort=("timestamp", DESCENDING))
                        if last_diff and last_diff["type"] == "remove":
                            continue
                        # Mark the removal (but only once)
                        mongo.db.cc_diff.insert_one({
                            "run_id": update_result.inserted_id,
                            "dgst": id,
                            "timestamp": start,
                            "type": "remove"
                        })
                # TODO: Issue a task for sending the notifications for the run here.
    except Exception as e:
        logging.error(str(e))
        end = datetime.now()
        mongo.db.cc_log.insert_one({
            "start_time": start,
            "end_time": end,
            "tool_version": tool_version,
            "length": len(dset),
            "ok": False
        })
    finally:
        rmtree(dset_path)
