import logging
import os
from abc import abstractmethod
from collections import Counter
from datetime import datetime
from importlib.metadata import version
from pathlib import Path
from shutil import rmtree
from typing import List, Optional, Set, Tuple, Type

import sec_certs
import sentry_sdk
from _operator import itemgetter
from flask import current_app
from jsondiff import diff
from pymongo import DESCENDING, InsertOne, ReplaceOne
from sec_certs.dataset.auxiliary_dataset_handling import (
    CPEDatasetHandler,
    CPEMatchDictHandler,
    CVEDatasetHandler,
    ProtectionProfileDatasetHandler,
)
from sec_certs.dataset.dataset import Dataset

from ... import mongo
from ..objformats import ObjFormat, StorageFormat, WorkingFormat

logger = logging.getLogger(__name__)


class Updater:  # pragma: no cover
    """
    Base class for dataset updaters (CC, FIPS, PP).

    The attributes should be set in the subclass.
    """

    collection: str
    diff_collection: str
    log_collection: str
    skip_update: bool
    dset_class: Type[Dataset]

    def make_dataset_paths(self) -> dict[str, Path]:
        """Setup paths from the config for the particular updater (CC, FIPS, PP)."""
        instance_path = Path(current_app.instance_path)
        ns = current_app.config.get_namespace("DATASET_PATH_")

        res = {
            "cve_path": instance_path / ns["cve"],
            "cpe_path": instance_path / ns["cpe"],
            "cpe_match_path": instance_path / ns["cpe_match"],
            "dset_path": instance_path / ns[self.collection],
            "dir_path": instance_path / ns[f"{self.collection}_dir"],
        }
        # Process DATASET_*_OUT_* entries, creating "output_path_*"
        out_prefix = f"{self.collection}_out"
        for key, value in ns.items():
            if key.startswith(out_prefix):
                suffix = key[len(out_prefix) :]
                res[f"output_path{suffix}"] = instance_path / value

        for document in ("report", "target", "cert", "profile"):
            doc_path = res["dir_path"] / document
            doc_path.mkdir(parents=True, exist_ok=True)
            res[document] = doc_path
            for format in ("pdf", "txt"):
                path = doc_path / format
                path.mkdir(parents=True, exist_ok=True)
                res[f"{document}_{format}"] = path

        return res

    def prepare_dataset_paths(self, dset: Dataset, paths: dict[str, Path]):
        if not dset.auxiliary_datasets_dir.exists():
            dset.auxiliary_datasets_dir.mkdir(parents=True)
        if paths["cve_path"].exists() and CVEDatasetHandler in dset.aux_handlers:
            cve_dset_path = dset.aux_handlers[CVEDatasetHandler].dset_path
            if cve_dset_path.exists():
                cve_dset_path.unlink()
            cve_dset_parent = cve_dset_path.parent
            cve_dset_parent.mkdir(parents=True, exist_ok=True)
            os.symlink(paths["cve_path"], cve_dset_path)
        if paths["cpe_path"].exists() and CPEDatasetHandler in dset.aux_handlers:
            cpe_dset_path = dset.aux_handlers[CPEDatasetHandler].dset_path
            if cpe_dset_path.exists():
                cpe_dset_path.unlink()
            cpe_dset_parent = cpe_dset_path.parent
            cpe_dset_parent.mkdir(parents=True, exist_ok=True)
            os.symlink(paths["cpe_path"], cpe_dset_path)
        if paths["cpe_match_path"].exists() and CPEMatchDictHandler in dset.aux_handlers:
            cpe_match_dset_path = dset.aux_handlers[CPEMatchDictHandler].dset_path
            if cpe_match_dset_path.exists():
                cpe_match_dset_path.unlink()
            cpe_match_dset_parent = cpe_match_dset_path.parent
            cpe_match_dset_parent.mkdir(parents=True, exist_ok=True)
            os.symlink(paths["cpe_match_path"], cpe_match_dset_path)
        if (
            "output_path_pp" in paths
            and paths["output_path_pp"].exists()
            and ProtectionProfileDatasetHandler in dset.aux_handlers
        ):
            pp_dset_path = dset.aux_handlers[ProtectionProfileDatasetHandler].dset_path
            if pp_dset_path.exists():
                pp_dset_path.unlink()
            pp_dset_parent = pp_dset_path.parent
            pp_dset_parent.mkdir(parents=True, exist_ok=True)
            os.symlink(paths["output_path_pp"], pp_dset_path)

    def process_new_certs(
        self, dset: Dataset, new_ids: Set[str], run_id, timestamp: datetime
    ) -> Tuple[List[object], List[object]]:
        res_col = []
        res_diff_col = []
        with sentry_sdk.start_span(op=f"{self.collection}.db.new", description="Process new certs."):
            logger.info(f"Processing {len(new_ids)} new certificates.")
            for id in new_ids:
                # Add a cert to DB
                cert_data = ObjFormat(dset[id]).to_raw_format().to_working_format().to_storage_format().get()
                cert_data["_id"] = cert_data["dgst"]
                res_col.append(InsertOne(cert_data))
                res_diff_col.append(
                    InsertOne(
                        {
                            "run_id": run_id,
                            "dgst": id,
                            "timestamp": timestamp,
                            "type": "new",
                            "diff": cert_data,
                        }
                    )
                )
        return res_col, res_diff_col

    def process_updated_certs(
        self, dset: Dataset, updated_ids: Set[str], run_id, timestamp: datetime
    ) -> Tuple[List[object], List[object]]:
        res_col = []
        res_diff_col = []
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
                    res_col.append(ReplaceOne({"_id": id}, storage_cert))
                    res_diff_col.append(
                        InsertOne(
                            {
                                "run_id": run_id,
                                "dgst": id,
                                "timestamp": timestamp,
                                "type": "change",
                                "diff": working_diff.to_storage_format().get(),
                            }
                        )
                    )
                    diffs += 1
                elif last_diff and last_diff["type"] == "remove":
                    # The cert did not change but came back from being marked removed
                    res_diff_col.append(
                        InsertOne(
                            {
                                "run_id": run_id,
                                "dgst": id,
                                "timestamp": timestamp,
                                "type": "back",
                            }
                        )
                    )
                    appearances += 1
            logger.info(
                f"Processed {diffs} changes in cert data, {appearances} reappearances of removed certs and {len(updated_ids) - diffs - appearances} unchanged."
            )
        return res_col, res_diff_col

    def process_removed_certs(self, dset: Dataset, removed_ids: Set[str], run_id, timestamp: datetime) -> List[object]:
        res_diff_col = []
        with sentry_sdk.start_span(op=f"{self.collection}.db.removed", description="Process removed certs."):
            logger.info(f"Processing {len(removed_ids)} removed certificates.")
            for id in removed_ids:
                # Find the last diff on this cert, if it is mark for removal, just continue
                last_diff = mongo.db[self.diff_collection].find_one({"dgst": id}, sort=[("timestamp", DESCENDING)])
                if last_diff and last_diff["type"] == "remove":
                    continue
                # Mark the removal (but only once)
                res_diff_col.append(
                    InsertOne(
                        {
                            "run_id": run_id,
                            "dgst": id,
                            "timestamp": timestamp,
                            "type": "remove",
                        }
                    )
                )
        return res_diff_col

    def insert_certs(self, collection: str, requests: List[object], ordered: bool = False):
        if requests:
            mongo.db[collection].bulk_write(requests, ordered=ordered)

    def count_cert_states(self, dset: Dataset) -> Counter[str]:
        cert_states: Counter[str] = Counter()
        for cert in dset:
            for attr in cert.state.serialized_attributes:
                val = getattr(cert.state, attr, False)
                if isinstance(val, bool):
                    cert_states[attr] += val
                elif hasattr(val, "serialized_attributes"):
                    for other_attr in val.serialized_attributes:
                        other_val = getattr(val, other_attr, False)
                        if isinstance(other_val, bool):
                            cert_states[attr + "_" + other_attr] += other_val
        return cert_states

    @abstractmethod
    def process(
        self, dset: Dataset, paths: dict[str, Path]
    ) -> Tuple[Set[Tuple[str, str]], Set[Tuple[str, str, Optional[str]]]]:
        """Process the dataset and return sets of cert IDs to reindex and update in the KB."""
        ...

    @abstractmethod
    def dataset_state(self, dset): ...

    @abstractmethod
    def notify(self, run_id): ...

    @abstractmethod
    def reindex(self, to_reindex): ...

    @abstractmethod
    def update_kb(self, to_update): ...

    @abstractmethod
    def archive(self, ids, paths): ...

    def update(self):
        try:
            from setuptools_scm import get_version

            tool_version = get_version(str(Path(sec_certs.__file__).parent.parent))
        except Exception:
            try:
                tool_version = version("sec-certs")
            except Exception:
                tool_version = ""
        start = datetime.now()
        paths = self.make_dataset_paths()

        if self.skip_update:
            logger.info("Skipping update due to config.")
            return
        else:
            dset = self.dset_class({}, paths["dset_path"], "dataset", "Description")

        self.prepare_dataset_paths(dset, paths)

        update_result = None
        run_doc = None
        try:
            # Process the certs
            to_reindex, to_update_kb = self.process(dset, paths)

            old_ids = set(map(itemgetter("_id"), mongo.db[self.collection].find({}, projection={"_id": 1})))
            current_ids = set(dset.certs.keys())

            new_ids = current_ids.difference(old_ids)
            removed_ids = old_ids.difference(current_ids)
            updated_ids = current_ids.intersection(old_ids)

            cert_states = self.count_cert_states(dset)

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
                res, res_diff = self.process_new_certs(dset, new_ids, update_result.inserted_id, start)
                self.insert_certs(self.collection, res, ordered=False)
                self.insert_certs(self.diff_collection, res_diff, ordered=False)

                res, res_diff = self.process_updated_certs(dset, updated_ids, update_result.inserted_id, start)
                self.insert_certs(self.collection, res, ordered=False)
                self.insert_certs(self.diff_collection, res_diff, ordered=False)

                res_diff = self.process_removed_certs(dset, removed_ids, update_result.inserted_id, start)
                self.insert_certs(self.diff_collection, res_diff, ordered=False)

            changed_ids = mongo.db[self.diff_collection].count_documents(
                {"run_id": update_result.inserted_id, "type": "change"}
            )
            mongo.db[self.log_collection].update_one(
                {"_id": update_result.inserted_id}, {"$set": {"stats.changed_ids": changed_ids}}
            )
            all_ids = list(map(itemgetter("_id"), mongo.db[self.collection].find({}, {"_id": 1})))

            self.notify(update_result.inserted_id)
            self.reindex(to_reindex)
            self.update_kb(to_update_kb)
            self.archive(all_ids, {name: str(path) for name, path in paths.items()})
        except Exception as e:
            logger.info(f"Run errored.")
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
