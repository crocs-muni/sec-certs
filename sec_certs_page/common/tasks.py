import json
import logging
import os
import secrets
from abc import abstractmethod
from collections import Counter
from datetime import datetime, timedelta
from functools import wraps
from importlib.metadata import version
from operator import itemgetter
from pathlib import Path
from shutil import rmtree
from typing import List, Set, Tuple, Type

import dramatiq
import sec_certs
import sentry_sdk
from bs4 import BeautifulSoup
from bson import ObjectId
from dramatiq.common import compute_backoff
from dramatiq.errors import Retry
from dramatiq.middleware import CurrentMessage
from dramatiq.middleware.retries import DEFAULT_MAX_BACKOFF, DEFAULT_MIN_BACKOFF
from filtercss import filter_css, parse_css
from flask import current_app, render_template, url_for
from jsondiff import diff, symbols
from pymongo import DESCENDING, InsertOne, ReplaceOne
from redis.exceptions import LockNotOwnedError
from redis.lock import Lock
from sec_certs.dataset.auxiliary_dataset_handling import (
    CPEDatasetHandler,
    CPEMatchDictHandler,
    CVEDatasetHandler,
    ProtectionProfileDatasetHandler,
)
from sec_certs.dataset.dataset import Dataset
from tqdm import tqdm

from .. import mail, mongo, redis, whoosh_index
from ..notifications.utils import Message
from .diffs import DiffRenderer
from .objformats import ObjFormat, StorageFormat, WorkingFormat, load
from .views import entry_file_path
from .webui import (
    add_file_to_knowledge_base,
    get_file_metadata,
    get_knowledge_base,
    update_file_data_content,
    update_file_in_knowledge_base,
    upload_file,
)

logger = logging.getLogger(__name__)


class Indexer:  # pragma: no cover
    dataset_path: Path
    cert_schema: str

    @abstractmethod
    def create_document(self, dgst, document, cert, content): ...

    def reindex(self, to_reindex):
        logger.info(f"Reindexing {len(to_reindex)} {self.cert_schema} files.")
        updated = 0
        with whoosh_index.writer() as writer, writer.searcher() as searcher:
            for i, (dgst, document_type) in enumerate(to_reindex):
                fpath = entry_file_path(dgst, self.dataset_path, document_type, "txt")
                try:
                    with fpath.open("r") as f:
                        content = f.read()
                except FileNotFoundError:
                    continue
                cert = mongo.db[self.cert_schema].find_one({"_id": dgst})
                docid = searcher.document_number(dgst=dgst, document_type=document_type)
                if docid is not None:
                    writer.delete_document(docid)
                writer.add_document(**self.create_document(dgst, document_type, cert, content))
                updated += 1
                if i % 100 == 0:
                    logger.info(f"{i}: updated {updated}.")
        logger.info(f"Reindexed {updated} out of {len(to_reindex)} {self.cert_schema} files.")


class Updater:  # pragma: no cover
    collection: str
    diff_collection: str
    log_collection: str
    skip_update: bool
    dset_class: Type[Dataset]

    def make_dataset_paths(self):
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

    @abstractmethod
    def process(self, dset, paths): ...

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

            cert_states = Counter()
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


class Notifier(DiffRenderer):
    def notify(self, run_id: str):
        run_oid = ObjectId(run_id)
        # Load up the diffs and certs
        change_diffs = {
            obj["dgst"]: load(obj) for obj in mongo.db[self.diff_collection].find({"run_id": run_oid, "type": "change"})
        }
        change_dgsts = list(change_diffs.keys())
        change_certs = {
            obj["dgst"]: load(obj) for obj in mongo.db[self.collection].find({"_id": {"$in": change_dgsts}})
        }
        new_diffs = {
            obj["dgst"]: load(obj) for obj in mongo.db[self.diff_collection].find({"run_id": run_oid, "type": "new"})
        }
        new_dgsts = list(new_diffs.keys())
        new_certs = {obj["dgst"]: load(obj) for obj in mongo.db[self.collection].find({"_id": {"$in": new_dgsts}})}

        # Render the individual diffs
        change_renders = {}
        for dgst in change_dgsts:
            change_renders[dgst] = self.render_diff(
                dgst, change_certs[dgst], change_diffs[dgst], linkback=True, name=True
            )
        new_renders = {}
        for dgst in new_dgsts:
            new_renders[dgst] = self.render_diff(dgst, new_certs[dgst], new_diffs[dgst], linkback=True)

        # Group the subscriptions by email
        change_sub_emails = mongo.db.subs.find(
            {"certificate.hashid": {"$in": change_dgsts}, "confirmed": True, "certificate.type": self.collection},
            {"email": 1},
        )
        new_sub_emails = mongo.db.subs.find(
            {"updates": "new", "confirmed": True},
            {"email": 1},
        )
        emails = {sub["email"] for sub in change_sub_emails} | {sub["email"] for sub in new_sub_emails}

        # Load Bootstrap CSS
        with current_app.open_resource("static/lib/bootstrap.min.css", "r") as f:
            bootstrap_css = f.read()
        bootstrap_parsed = parse_css(bootstrap_css)

        # Get the run date
        run = mongo.db[self.log_collection].find_one({"_id": run_oid})
        run_date = run["start_time"].strftime("%d.%m.")

        # Go over the subscribed emails
        for email in emails:
            cards = []
            urls = []
            email_token = None

            # Go over the subscriptions for a given email and accumulate its rendered diffs
            some_changes = False
            subscriptions = list(
                mongo.db.subs.find(
                    {
                        "certificate.hashid": {"$in": change_dgsts},
                        "confirmed": True,
                        "email": email,
                        "certificate.type": self.collection,
                    }
                )
            )
            if subscriptions:
                email_token = subscriptions[0]["email_token"]
                for sub in subscriptions:
                    dgst = sub["certificate"]["hashid"]
                    diff = change_diffs[dgst]
                    render = change_renders[dgst]
                    if sub["updates"] == "vuln":
                        # This is a vuln only subscription so figure out if the change is in a vuln.
                        if h := diff["diff"][symbols.update].get("heuristics"):
                            for action, val in h.items():
                                if "related_cves" in val:
                                    break
                            else:
                                continue
                        else:
                            continue
                    cards.append(render)
                    urls.append(url_for(f"{self.collection}.entry", hashid=dgst, _external=True))
                    some_changes = True

            # If the user is subscribed for new certs, add them.
            some_new = False
            new_subscription = next(
                iter(mongo.db.subs.find({"confirmed": True, "email": email, "updates": "new"})), None
            )
            if new_subscription:
                email_token = new_subscription["email_token"]
                for dgst, render in new_renders.items():
                    cards.append(render)
                    urls.append(url_for(f"{self.collection}.entry", hashid=dgst, _external=True))
                    some_new = True
            if not some_changes and not some_new:
                # Nothing to send, due to only "vuln" subscription and non-vuln diffs
                continue
            if email_token is None:
                logger.error(f"Email token undefined for {email}.")
                continue
            # Render diffs into body template
            email_core_html = render_template(
                "notifications/email/notification_email.html.jinja2",
                cards=cards,
                email_token=email_token,
                changes=some_changes,
                new=some_new,
            )
            # Filter out unused CSS rules
            cleaned_css = filter_css(bootstrap_parsed, email_core_html)
            # Inject final CSS into html
            soup = BeautifulSoup(email_core_html, "lxml")
            css_tag = soup.new_tag("style")
            css_tag.insert(0, soup.new_string(cleaned_css))
            soup.find("meta").insert_after(css_tag)
            email_html = soup.prettify(formatter="html")
            # Render plaintext part
            email_plain = render_template(
                "notifications/email/notification_email.txt.jinja2",
                email_token=email_token,
                urls=urls,
                changes=some_changes,
                new=some_new,
            )
            # Send out the message
            msg = Message(
                f"Certificate changes from {run_date} | sec-certs.org", [email], body=email_plain, html=email_html
            )
            mail.send(msg)


class Archiver:  # pragma: no cover
    """
    Dataset
    =======

    ├── auxiliary_datasets          (not PP)
    │   ├── cpe_dataset.json
    │   ├── cve_dataset.json
    │   ├── cpe_match.json
    │   ├── algorithms.json         (only FIPS)
    │   ├── cc_scheme.json          (only CC)
    │   ├── protection_profiles     (only CC)
    │   │   ├── reports
    │   │   │   ├── pdf
    │   │   │   └── txt
    │   │   ├── pps
    │   │   │   ├── pdf
    │   │   │   └── txt
    │   │   └── dataset.json
    │   └── maintenances            (only CC)
    │       ├── certs
    │       │   ├── reports
    │       │   │   ├── pdf
    │       │   │   └── txt
    │       │   └── targets
    │       │       ├── pdf
    │       │       └── txt
    │       └── maintenance_updates.json
    ├── certs
    │   ├── reports                 (not FIPS)
    │   │   ├── pdf
    │   │   └── txt
    │   ├── targets                 (only CC and FIPS)
    │   │   ├── pdf
    │   │   └── txt
    │   ├── pps                     (only PP)
    │   │   ├── pdf
    │   │   └── txt
    │   └── certificates            (only CC)
    │       ├── pdf
    │       └── txt
    ├── reports                     (only PP)
    │   ├── pdf
    │   └── txt
    ├── pps                         (only PP)
    │   ├── pdf
    │   └── txt
    ├── pp.json                     (only PP)
    └── dataset.json
    """

    def map_artifact_dir(self, ids, fromdir, todir):
        for format in ("pdf", "txt"):
            src = Path(fromdir) / format
            dst = Path(todir) / format
            dst.mkdir(parents=True, exist_ok=True)
            for id in ids:
                name = f"{id}.{format}"
                from_file = src / name
                to_file = dst / name
                if from_file.exists():
                    os.symlink(from_file, to_file)

    def archive(self, ids, path, paths):
        pass


class KBUpdater:  # pragma: no cover
    collection: str
    dataset_path: Path

    def _load_kb(self, kbid):
        if kbid is None:
            return {}
        kb = get_knowledge_base(kbid)
        fmap = {}
        for file in kb["files"]:
            id = file["id"]
            name = file["meta"]["name"]
            updated = file["updated_at"]
            fmap[name] = (id, updated)
        return fmap

    def update(self, to_update):
        coll = self.collection.upper()
        reports_kbid = current_app.config.get(f"WEBUI_COLLECTION_{coll}_REPORTS", None)
        targets_kbid = current_app.config.get(f"WEBUI_COLLECTION_{coll}_TARGETS", None)
        reports_fmap = self._load_kb(reports_kbid)
        targets_fmap = self._load_kb(targets_kbid)

        for digest, document, file_id in tqdm(to_update):
            if document == "report":
                kb = reports_kbid
                fmap = reports_fmap
            elif document == "target":
                kb = targets_kbid
                fmap = targets_fmap
            else:
                continue

            # We have no knowledge base for this document type
            if kb is None:
                continue
            # Get file contents
            fpath = entry_file_path(digest, self.dataset_path, document, "txt")
            if not fpath.exists() or not fpath.is_file():
                continue
            # Check if the file is empty
            stat = fpath.stat()
            if stat.st_size == 0:
                continue
            # Check whether we have the file under some id
            name = f"{digest}.txt"
            if name in fmap:
                file_id, updated_at = fmap[name]
            elif file_id is not None:
                meta = get_file_metadata(file_id)
                updated_at = meta["updated_at"]
            else:
                updated_at = None

            if file_id is None:
                # Create a new file
                resp = upload_file(fpath)
                print("Added", resp["id"], digest, document)
                # Add it to the kb
                resp = add_file_to_knowledge_base(kb, resp["id"])
            else:
                mtime = int(stat.st_mtime)
                # Check if the file is already in the KB
                if mtime <= updated_at:
                    print("Same", file_id, digest, document, mtime, updated_at)
                    continue
                # Then update the file with new contents
                with fpath.open("rb") as f:
                    resp = update_file_data_content(file_id, f)
                print("Updated", file_id, digest, document)
                # Then trigger also kb update
                resp = update_file_in_knowledge_base(kb, file_id)


def no_simultaneous_execution(lock_name: str, abort: bool = False, timeout: float = 60 * 10):  # pragma: no cover
    """
    A decorator that prevents simultaneous execution of more than one actor.

    :param lock_name:
    :param abort: Whether to abort task if lock cannot be acquired immediately.
    :param timeout: Lock timeout (in seconds). The lock will be automatically released after.
    :return:
    """

    def deco(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            lock: Lock = redis.lock(lock_name, timeout=timeout)
            acq = lock.acquire(blocking=not abort)
            if not acq:
                logger.warning(f"Failed to acquire lock: {lock_name}")
                return
            try:
                return f(*args, **kwargs)
            finally:
                try:
                    lock.release()
                except LockNotOwnedError:
                    logger.warning(f"Releasing lock late: {lock_name}")

        return wrapper

    return deco


def single_queue(queue_name: str, timeout: float = 60 * 10):  # pragma: no cover
    """
    A decorator that prevents simultaneous execution of more than one actor in a queue.
    It does so by requeueing the actor.
    """

    def deco(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            msg = CurrentMessage.get_current_message()
            if msg is None:
                # If we are testing and not in a worker, just execute
                return f(*args, **kwargs)
            retries = msg.options.get("retries", 0)
            lock: Lock = redis.lock(queue_name, timeout=timeout)
            acq = lock.acquire(blocking=False)
            if not acq:
                _, delay = compute_backoff(retries, factor=DEFAULT_MIN_BACKOFF, max_backoff=DEFAULT_MAX_BACKOFF)
                raise Retry(message=f"Failed to acquire queue lock: {queue_name}", delay=delay)
            try:
                return f(*args, **kwargs)
            finally:
                try:
                    lock.release()
                except LockNotOwnedError:
                    logger.warning(f"Releasing queue lock late: {queue_name}")

        return wrapper

    return deco


def task(task_name):
    def deco(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            with sentry_sdk.start_transaction(op="dramatiq", name=task_name):
                tid = secrets.token_hex(16)
                start = datetime.now()
                data = {"name": task_name, "start_time": start.isoformat()}
                logger.info(f'Starting task ({task_name}), tid="{tid}"')
                redis.set(tid, json.dumps(data))
                redis.sadd("tasks", tid)
                try:
                    return f(*args, **kwargs)
                finally:
                    logger.info(f'Ending task ({task_name}), tid="{tid}", took {datetime.now() - start}')
                    redis.srem("tasks", tid)
                    redis.delete(tid)

        return wrapper

    return deco


def actor(name, lock_name, queue_name, timeout):
    """
    Usual dramatiq actor setup.
    """

    def deco(f):
        @wraps(f)
        @dramatiq.actor(
            actor_name=name,
            queue_name=queue_name,
            max_retries=0,
            retry_when=lambda retries, exc: isinstance(exc, Retry),
            time_limit=timeout.total_seconds() * 1000,
        )
        @no_simultaneous_execution(lock_name, abort=True, timeout=(timeout + timedelta(minutes=10)).total_seconds())
        @single_queue(queue_name, timeout=(timeout + timedelta(minutes=10)).total_seconds())
        @task(name)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)

        return wrapper

    return deco
