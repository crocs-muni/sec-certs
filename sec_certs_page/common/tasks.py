import os
from abc import abstractmethod
from collections import Counter
from datetime import datetime
from functools import wraps
from itertools import product
from operator import itemgetter
from pathlib import Path
from shutil import rmtree
from typing import Type

import sentry_sdk
from celery.utils.log import get_task_logger
from flask import current_app
from jsondiff import diff
from pkg_resources import get_distribution
from pymongo import DESCENDING
from sec_certs.dataset.dataset import Dataset

from .. import mongo, redis, whoosh_index
from .objformats import ObjFormat, StorageFormat, WorkingFormat
from .views import entry_file_path

logger = get_task_logger(__name__)


class Indexer:  # pragma: no cover
    dataset_path: Path
    cert_schema: str

    @abstractmethod
    def create_document(self, dgst, document, cert, content):
        ...

    def reindex(self, to_reindex):
        logger.info(f"Reindexing {len(to_reindex)} files.")
        with whoosh_index.writer() as writer:
            for dgst, document in to_reindex:
                fpath = entry_file_path(dgst, self.dataset_path, document, "txt")
                try:
                    with fpath.open("r") as f:
                        content = f.read()
                except FileNotFoundError:
                    continue
                cert = mongo.db[self.cert_schema].find_one({"_id": dgst})
                writer.update_document(**self.create_document(dgst, document, cert, content))


class Updater:  # pragma: no cover
    collection: str
    diff_collection: str
    log_collection: str
    skip_update: bool
    dset_class: Type[Dataset]

    def make_dataset_paths(self):  # pragma: no cover
        instance_path = Path(current_app.instance_path)
        ns = current_app.config.get_namespace("DATASET_PATH_")

        res = {
            "cve_path": instance_path / ns["cve"],
            "cpe_path": instance_path / ns["cpe"],
            "dset_path": instance_path / ns[self.collection],
            "output_path": instance_path / ns[f"{self.collection}_out"],
            "dir_path": instance_path / ns[f"{self.collection}_dir"],
        }

        for document, format in product(("report", "target"), ("pdf", "txt")):
            path = res["dir_path"] / document / format
            path.mkdir(parents=True, exist_ok=True)
            res[f"{document}_{format}"] = path

        return res

    def process_new_certs(self, dset, new_ids, run_id, timestamp):  # pragma: no cover
        with sentry_sdk.start_span(op=f"{self.collection}.db.new", description="Process new certs."):
            logger.info(f"Processing {len(new_ids)} new certificates.")
            for id in new_ids:
                # Add a cert to DB
                cert_data = ObjFormat(dset[id]).to_raw_format().to_working_format().to_storage_format().get()
                cert_data["_id"] = cert_data["dgst"]
                mongo.db[self.collection].insert_one(cert_data)
                mongo.db[self.diff_collection].insert_one(
                    {
                        "run_id": run_id,
                        "dgst": id,
                        "timestamp": timestamp,
                        "type": "new",
                        "diff": cert_data,
                    }
                )

    def process_updated_certs(self, dset, updated_ids, run_id, timestamp):  # pragma: no cover
        with sentry_sdk.start_span(op=f"{self.collection}.db.updated", description="Process updated certs."):
            logger.info(f"Processing {len(updated_ids)} updated certificates.")
            diffs = 0
            appearances = 0
            for id in updated_ids:
                # Process an updated cert, it can also be that a "removed" cert reappeared
                working_current_cert = (
                    StorageFormat(mongo.db[self.collection].find_one({"_id": id}, {"_id": 0})).to_working_format().get()
                )
                working_cert = ObjFormat(dset[id]).to_raw_format().to_working_format()
                working_cert_data = working_cert.get()
                # Find the last diff
                last_diff = mongo.db[self.diff_collection].find_one({"dgst": id}, sort=[("timestamp", DESCENDING)])
                if cert_diff := diff(working_current_cert, working_cert_data, syntax="explicit"):
                    working_diff = WorkingFormat(cert_diff)
                    storage_cert = working_cert.to_storage_format().get()
                    storage_cert["_id"] = id
                    # The cert changed, issue an update
                    mongo.db[self.collection].replace_one({"_id": id}, storage_cert)
                    mongo.db[self.diff_collection].insert_one(
                        {
                            "run_id": run_id,
                            "dgst": id,
                            "timestamp": timestamp,
                            "type": "change",
                            "diff": working_diff.to_storage_format().get(),
                        }
                    )
                    diffs += 1
                elif last_diff and last_diff["type"] == "remove":
                    # The cert did not change but came back from being marked removed
                    mongo.db[self.diff_collection].insert_one(
                        {
                            "run_id": run_id,
                            "dgst": id,
                            "timestamp": timestamp,
                            "type": "back",
                        }
                    )
                    appearances += 1
            logger.info(
                f"Processed {diffs} changes in cert data, {appearances} reappearances of removed certs and {len(updated_ids) - diffs - appearances} unchanged."
            )

    def process_removed_certs(self, dset, removed_ids, run_id, timestamp):  # pragma: no cover
        with sentry_sdk.start_span(op=f"{self.collection}.db.removed", description="Process removed certs."):
            logger.info(f"Processing {len(removed_ids)} removed certificates.")
            for id in removed_ids:
                # Find the last diff on this cert, if it is mark for removal, just continue
                last_diff = mongo.db[self.diff_collection].find_one({"dgst": id}, sort=[("timestamp", DESCENDING)])
                if last_diff and last_diff["type"] == "remove":
                    continue
                # Mark the removal (but only once)
                mongo.db[self.diff_collection].insert_one(
                    {
                        "run_id": run_id,
                        "dgst": id,
                        "timestamp": timestamp,
                        "type": "remove",
                    }
                )

    @abstractmethod
    def process(self, dset, paths):
        ...

    @abstractmethod
    def dataset_state(self, dset):
        ...

    @abstractmethod
    def notify(self, run_id):
        ...

    @abstractmethod
    def reindex(self, to_reindex):
        ...

    def update(self):
        tool_version = get_distribution("sec-certs").version
        start = datetime.now()
        paths = self.make_dataset_paths()

        skip_update = self.skip_update and paths["output_path"].exists()
        if skip_update:
            dset = self.dset_class.from_json(paths["output_path"])
            dset.root_dir = paths["dset_path"]
            dset.set_local_paths()
        else:
            dset = self.dset_class({}, paths["dset_path"], "dataset", "Description")

        if not dset.auxillary_datasets_dir.exists():
            dset.auxillary_datasets_dir.mkdir(parents=True)
        if paths["cve_path"].exists():
            os.symlink(paths["cve_path"], dset.cve_dataset_path)
        if paths["cpe_path"].exists():
            os.symlink(paths["cpe_path"], dset.cpe_dataset_path)

        update_result = None
        run_doc = None
        try:
            # Process the certs
            to_reindex = self.process(dset, paths)

            old_ids = set(map(itemgetter("_id"), mongo.db[self.collection].find({}, projection={"_id": 1})))
            current_ids = set(dset.certs.keys())

            new_ids = current_ids.difference(old_ids)
            removed_ids = old_ids.difference(current_ids)
            updated_ids = current_ids.intersection(old_ids)

            cert_states = Counter(key for cert in dset for key in cert.state.to_dict() if cert.state.to_dict()[key])

            # Store the success in the update log
            end = datetime.now()
            run_doc = {
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
            if dset_state := self.dataset_state(dset):
                run_doc["state"] = dset_state
            update_result = mongo.db[self.log_collection].insert_one(run_doc)
            logger.info(f"Finished run {update_result.inserted_id}.")

            # TODO: Take dataset and certificate state into account when processing into DB.

            with sentry_sdk.start_span(op=f"{self.collection}.db", description="Process certs into DB."):
                self.process_new_certs(dset, new_ids, update_result.inserted_id, start)
                self.process_updated_certs(dset, updated_ids, update_result.inserted_id, start)
                self.process_removed_certs(dset, removed_ids, update_result.inserted_id, start)

            self.notify(update_result.inserted_id)
            self.reindex(to_reindex)
        except Exception as e:
            # Store the failure in the update log
            end = datetime.now()
            result = {
                "start_time": start,
                "end_time": end,
                "tool_version": tool_version,
                "length": len(dset),
                "ok": False,
                "error": str(e),
            }
            if dset_state := self.dataset_state(dset):
                result["state"] = dset_state

            if update_result is None:
                mongo.db[self.log_collection].insert_one(result)
            else:
                result["stats"] = run_doc["stats"]
                mongo.db[self.log_collection].replace_one({"_id": update_result.inserted_id}, result)
            raise e
        finally:
            rmtree(paths["dset_path"], ignore_errors=True)


def no_simultaneous_execution(lock_name):
    def deco(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            lock = redis.lock(lock_name, sleep=1, timeout=3600 * 8)
            lock.acquire()
            try:
                return f(*args, **kwargs)
            finally:
                lock.release()

        return wrapper

    return deco
