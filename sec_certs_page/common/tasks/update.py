import logging
from _operator import itemgetter
from abc import abstractmethod
from collections import Counter
from datetime import datetime
from importlib.metadata import version
from pathlib import Path

import sec_certs
import sentry_sdk
from flask import current_app
from jsondiff import diff
from pymongo import DESCENDING, InsertOne, ReplaceOne
from sec_certs.dataset.auxiliary_dataset_handling import (
    CPEDatasetHandler,
    CPEMatchDictHandler,
    CVEDatasetHandler,
    ProcessingMode,
    ProtectionProfileDatasetHandler,
)
from sec_certs.dataset.dataset import Dataset

from ... import mongo
from ..objformats import ObjFormat, StorageFormat, WorkingFormat
from ..sentry import suppress_child_spans

logger = logging.getLogger(__name__)


def tool_version() -> str:
    try:
        from setuptools_scm import get_version

        return get_version(str(Path(sec_certs.__file__).parent.parent))
    except Exception:
        try:
            return version("sec-certs")
        except Exception:
            return ""


class Updater:  # pragma: no cover
    """
    Base class for dataset updaters (CC, FIPS, PP).

    The attributes should be set in the subclass.
    """

    collection: str
    diff_collection: str
    log_collection: str
    skip_update: bool
    dset_class: type[Dataset]
    dset_folders: dict[str, str]

    @abstractmethod
    def write_auxiliary_json(self, dset: Dataset, paths: dict[str, Path]) -> None: ...

    @abstractmethod
    def dataset_state(self, dset): ...

    @abstractmethod
    def notify(self, run_id): ...

    @abstractmethod
    def reindex(self, to_reindex): ...

    @abstractmethod
    def archive(self, ids, paths): ...

    def update(self):
        if self.skip_update:
            logger.info("Skipping weekly update due to config.")
            return

        paths = self.make_dataset_paths()
        dset = self.get_dataset(paths["dset_path"])
        self.prepare_dataset_paths(dset, paths)

        run = self.create_run()
        try:
            self.process(dset, paths)

            ids = self.sort_ids(dset)
            changed_ids = self.store_certs(dset, ids, run["_id"], run["start_time"])
            run |= {
                "stats": {
                    "new_certs": len(ids["new"]),
                    "removed_ids": len(ids["removed"]),
                    "updated_ids": len(ids["updated"]),
                    "changed_ids": len(changed_ids),
                    "cert_states": dict(self.count_cert_states(dset)),
                },
            }

            self.notify(run["_id"])
            self.reindex(ids["new"] | changed_ids)
            self.archive(
                list(map(itemgetter("_id"), mongo.db[self.collection].find({}, {"_id": 1}))),
                {name: str(path) for name, path in paths.items()},
            )
            run["ok"] = True
            logger.info(f"Finished run {run['_id']}.")
        except Exception as e:
            logger.info("Run errored.")
            run["error"] = str(e)
            raise
        finally:
            run |= {"end_time": datetime.now(), "length": len(dset)}
            if dset_state := self.dataset_state(dset):
                run["state"] = dset_state
            self.log_run(run)

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

        for document in self.dset_folders:
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
            cve_dset_path.symlink_to(paths["cve_path"])
        if paths["cpe_path"].exists() and CPEDatasetHandler in dset.aux_handlers:
            cpe_dset_path = dset.aux_handlers[CPEDatasetHandler].dset_path
            if cpe_dset_path.exists():
                cpe_dset_path.unlink()
            cpe_dset_parent = cpe_dset_path.parent
            cpe_dset_parent.mkdir(parents=True, exist_ok=True)
            cpe_dset_path.symlink_to(paths["cpe_path"])
        if paths["cpe_match_path"].exists() and CPEMatchDictHandler in dset.aux_handlers:
            cpe_match_dset_path = dset.aux_handlers[CPEMatchDictHandler].dset_path
            if cpe_match_dset_path.exists():
                cpe_match_dset_path.unlink()
            cpe_match_dset_parent = cpe_match_dset_path.parent
            cpe_match_dset_parent.mkdir(parents=True, exist_ok=True)
            cpe_match_dset_path.symlink_to(paths["cpe_match_path"])
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
            pp_dset_path.symlink_to(paths["output_path_pp"])

    def get_dataset(self, path: Path) -> Dataset:
        dset_json = path / "dataset.json"
        if dset_json.exists():
            dset = self.dset_class.from_json(dset_json)
            dset.name = "dataset"
        else:
            dset = self.dset_class(root_dir=path, name="dataset")

        return dset

    def process(self, dset: Dataset, paths: dict[str, Path]) -> None:
        collection = self.collection
        with sentry_sdk.start_span(op=f"{collection}.all", name=f"Get full {collection.upper()} dataset"):
            self.run_pipeline(dset)
            with sentry_sdk.start_span(op=f"{collection}.publish", name="Publish artifacts"), suppress_child_spans():
                self.publish_artifacts(dset, paths)
            with sentry_sdk.start_span(op=f"{collection}.write_json", name="Write JSON"), suppress_child_spans():
                dset.to_json(paths["output_path"])
                self.write_auxiliary_json(dset, paths)

    def run_pipeline(self, dset: Dataset) -> None:
        collection = self.collection
        with sentry_sdk.start_span(op=f"{collection}.get_certs", name="Get certs from web"), suppress_child_spans():
            dset.get_certs_from_web(carry_processing_results=True)
        with (
            sentry_sdk.start_span(op=f"{collection}.auxiliary_datasets", name="Process auxiliary datasets"),
            suppress_child_spans(),
        ):
            dset.process_auxiliary_datasets(ProcessingMode.LOAD)
        with (
            sentry_sdk.start_span(op=f"{collection}.download_artifacts", name="Download artifacts"),
            suppress_child_spans(),
        ):
            dset.download_all_artifacts(fresh=True)
        with sentry_sdk.start_span(op=f"{collection}.convert_pdfs", name="Convert pdfs"), suppress_child_spans():
            dset.convert_all_pdfs(fresh=False)
        with sentry_sdk.start_span(op=f"{collection}.analyze", name="Analyze certificates"), suppress_child_spans():
            dset.analyze_certificates(fresh=False)
        with sentry_sdk.start_span(op=f"{collection}.write_dataset", name="Write dataset"), suppress_child_spans():
            dset.to_json()

    def publish_artifacts(self, dset: Dataset, paths: dict[str, Path]) -> None:
        for folder, document in self.dset_folders.items():
            for format in ("pdf", "txt"):
                dset_dir = getattr(dset, f"{document}_{format}_dir")
                if not dset_dir.exists():
                    continue
                page_dir = paths[f"{folder}_{format}"]
                for artifact in dset_dir.glob(f"*.{format}"):
                    published_artifact = page_dir / artifact.name
                    tmp = published_artifact.with_name(f"{artifact.name}.tmp")
                    tmp.unlink(missing_ok=True)
                    tmp.hardlink_to(artifact)
                    tmp.replace(published_artifact)

    def sort_ids(self, dset: Dataset) -> dict[str, set[str]]:
        stored_ids = set(map(itemgetter("_id"), mongo.db[self.collection].find({}, projection={"_id": 1})))
        current_ids = set(dset.certs.keys())
        return {
            "new": current_ids - stored_ids,
            "updated": current_ids & stored_ids,
            "removed": stored_ids - current_ids,
        }

    def store_certs(self, dset: Dataset, ids: dict[str, set[str]], run_id, timestamp: datetime) -> set[str]:
        with sentry_sdk.start_span(op=f"{self.collection}.db", name="Process certs into DB."):
            res, res_diff = self.process_new_certs(dset, ids["new"], run_id, timestamp)
            self.insert_certs(self.collection, res)
            self.insert_certs(self.diff_collection, res_diff)

            res, res_diff, changed_ids = self.process_updated_certs(dset, ids["updated"], run_id, timestamp)
            self.insert_certs(self.collection, res)
            self.insert_certs(self.diff_collection, res_diff)

            res_diff = self.process_removed_certs(dset, ids["removed"], run_id, timestamp)
            self.insert_certs(self.diff_collection, res_diff)

        return changed_ids

    def process_new_certs(
        self, dset: Dataset, new_ids: set[str], run_id, timestamp: datetime
    ) -> tuple[list[object], list[object]]:
        res_col = []
        res_diff_col = []
        with sentry_sdk.start_span(op=f"{self.collection}.db.new", name="Process new certs."):
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
        self, dset: Dataset, updated_ids: set[str], run_id, timestamp: datetime
    ) -> tuple[list[object], list[object], set[str]]:
        res_col = []
        res_diff_col = []
        changed_ids: set[str] = set()
        with sentry_sdk.start_span(op=f"{self.collection}.db.updated", name="Process updated certs."):
            logger.info(f"Processing {len(updated_ids)} updated certificates.")
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
                    changed_ids.add(id)
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
                f"Processed {len(changed_ids)} changes in cert data, {appearances} reappearances of removed certs and {len(updated_ids) - len(changed_ids) - appearances} unchanged."
            )
        return res_col, res_diff_col, changed_ids

    def process_removed_certs(self, dset: Dataset, removed_ids: set[str], run_id, timestamp: datetime) -> list[object]:
        res_diff_col = []
        with sentry_sdk.start_span(op=f"{self.collection}.db.removed", name="Process removed certs."):
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

    def insert_certs(self, collection: str, requests: list[object], ordered: bool = False):
        if requests:
            mongo.db[collection].bulk_write(requests, ordered=ordered)

    def create_run(self) -> dict:
        run = {"start_time": datetime.now(), "tool_version": tool_version(), "ok": False}
        run["_id"] = mongo.db[self.log_collection].insert_one(run).inserted_id
        return run

    def log_run(self, run: dict) -> None:
        mongo.db[self.log_collection].replace_one({"_id": run["_id"]}, run)

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
