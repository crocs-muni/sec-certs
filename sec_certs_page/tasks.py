import gzip
import json
import logging
from logging import Logger
from operator import itemgetter
from pathlib import Path

import dramatiq
import sentry_sdk
from flask import current_app
from periodiq import cron
from pymongo import ReplaceOne
from sec_certs.configuration import config
from sec_certs.dataset.cpe import CPEDataset
from sec_certs.dataset.cve import CVEDataset
from sec_certs.utils.nvd_dataset_builder import CpeMatchNvdDatasetBuilder, CpeNvdDatasetBuilder, CveNvdDatasetBuilder

from . import mongo
from .cc.tasks import update_data as update_cc_data
from .common.objformats import ObjFormat
from .common.tasks import no_simultaneous_execution
from .fips.tasks import update_data as update_fips_data
from .fips.tasks import update_iut_data, update_mip_data
from .notifications.tasks import cleanup_subscriptions

logger: Logger = logging.getLogger(__name__)


@dramatiq.actor(max_retries=0, actor_name="cve_update")
@no_simultaneous_execution("cve_update", abort=True, timeout=3600)
def update_cve_data() -> None:  # pragma: no cover
    instance_path = Path(current_app.instance_path)
    cve_path = instance_path / current_app.config["DATASET_PATH_CVE"]
    cve_compressed_path = instance_path / current_app.config["DATASET_PATH_CVE_COMPRESSED"]

    logger.info("Getting CVEs.")
    with sentry_sdk.start_span(op="cve.get", description="Get CVEs."):
        if cve_path.exists():
            cve_dset = CVEDataset.from_json(cve_path)
        else:
            cve_dset = CVEDataset(json_path=cve_path)
        with CveNvdDatasetBuilder(api_key=config.nvd_api_key) as builder:
            cve_dset = builder.build_dataset(cve_dset)
    logger.info(f"Got {len(cve_dset)} CVEs.")

    logger.info("Saving CVE dataset.")
    with sentry_sdk.start_span(op="cve.save", description="Save CVEs."):
        cve_dset.to_json(cve_path)
        cve_dset.to_json(cve_compressed_path, compress=True)

    logger.info("Inserting CVEs.")
    with sentry_sdk.start_span(op="cve.insert", description="Insert CVEs into DB."):
        old_ids = set(map(itemgetter("_id"), mongo.db.cve.find({}, ["_id"])))
        new_ids = set()
        cves = list(cve_dset)
        for i in range(0, len(cve_dset), 10000):
            chunk = []
            for cve in cves[i : i + 10000]:
                cve_data = ObjFormat(cve).to_raw_format().to_working_format().to_storage_format().get()
                cve_data["_id"] = cve.cve_id
                new_ids.add(cve.cve_id)
                chunk.append(ReplaceOne({"_id": cve.cve_id}, cve_data, upsert=True))
            res = mongo.db.cve.bulk_write(chunk, ordered=False)
            res_vals = ", ".join(f"{k} = {v}" for k, v in res.bulk_api_result.items() if k != "upserted")
            logger.info(f"Inserted chunk: {res_vals}")

    logger.info("Cleaning up old CVEs.")
    with sentry_sdk.start_span(op="cve.cleanup", description="Cleanup CVEs from DB."):
        res = mongo.db.cve.delete_many({"_id": {"$in": list(old_ids - new_ids)}})
        logger.info(f"Cleaned up {res.deleted_count} CVEs.")


@dramatiq.actor(max_retries=0, actor_name="cpe_update")
@no_simultaneous_execution("cpe_update", abort=True, timeout=3600)
def update_cpe_data() -> None:  # pragma: no cover
    instance_path = Path(current_app.instance_path)
    cpe_path = instance_path / current_app.config["DATASET_PATH_CPE"]
    cpe_compressed_path = instance_path / current_app.config["DATASET_PATH_CPE_COMPRESSED"]

    logger.info("Getting CPEs.")
    with sentry_sdk.start_span(op="cpe.get", description="Get CPEs."):
        if cpe_path.exists():
            cpe_dset = CPEDataset.from_json(cpe_path)
        else:
            cpe_dset = CPEDataset(json_path=cpe_path)

        with CpeNvdDatasetBuilder(api_key=config.nvd_api_key) as builder:
            cpe_dset = builder.build_dataset(cpe_dset)
    logger.info(f"Got {len(cpe_dset)} CPEs.")

    logger.info("Saving CPE dataset.")
    with sentry_sdk.start_span(op="cpe.save", description="Save CPEs."):
        cpe_dset.to_json(cpe_path)
        cpe_dset.to_json(cpe_compressed_path, compress=True)

    logger.info("Inserting CPEs.")
    with sentry_sdk.start_span(op="cpe.insert", description="Insert CPEs into DB."):
        old_uris = set(map(itemgetter("_id"), mongo.db.cpe.find({}, ["_id"])))
        new_uris = set()
        cpes = list(cpe_dset)
        for i in range(0, len(cpe_dset), 10000):
            chunk = []
            for cpe in cpes[i : i + 10000]:
                cpe_data = ObjFormat(cpe).to_raw_format().to_working_format().to_storage_format().get()
                cpe_data["_id"] = cpe.uri
                new_uris.add(cpe.uri)
                chunk.append(ReplaceOne({"_id": cpe.uri}, cpe_data, upsert=True))
        res = mongo.db.cpe.bulk_write(chunk, ordered=False)
        res_vals = ", ".join(f"{k} = {v}" for k, v in res.bulk_api_result.items() if k != "upserted")
        logger.info(f"Inserted chunk: {res_vals}")

    logger.info("Cleaning up old CPEs.")
    with sentry_sdk.start_span(op="cpe.cleanup", description="Cleanup CPEs from DB."):
        res = mongo.db.cpe.delete_many({"_id": {"$in": list(old_uris - new_uris)}})
        logger.info(f"Cleaned up {res.deleted_count} CPEs.")


@dramatiq.actor(max_retries=0, actor_name="cpe_match_update")
@no_simultaneous_execution("cpe_match_update", abort=True, timeout=3600)
def update_cpe_match_data() -> None:  # pragma: no cover
    instance_path = Path(current_app.instance_path)
    match_path = instance_path / current_app.config["DATASET_PATH_CPE_MATCH"]
    match_compressed_path = instance_path / current_app.config["DATASET_PATH_CPE_MATCH_COMPRESSED"]

    logger.info("Getting CPE matches.")
    with sentry_sdk.start_span(op="cpe_match.get", description="Get CPE matches."):
        if match_path.exists():
            with match_path.open("r") as handle:
                match_dset = json.load(handle)
        else:
            match_dset = None

        with CpeMatchNvdDatasetBuilder(api_key=config.nvd_api_key) as builder:
            match_dset = builder.build_dataset(match_dset)

    logger.info("Saving CPE match dataset.")
    with sentry_sdk.start_span(op="cpe_match.save", description="Save CPE matches."):
        with match_path.open("w", encoding="UTF-8") as handle:
            json.dump(match_dset, handle, indent=4)
        with gzip.open(match_compressed_path, "wb", encoding="UTF-8") as gzip_handle:
            json.dump(match_dset, gzip_handle, indent=4)  # type: ignore


@dramatiq.actor(periodic=cron("@weekly"))
def run_updates_weekly() -> None:  # pragma: no cover
    (
        update_cc_data.message_with_options(pipe_ignore=True) | update_fips_data.message_with_options(pipe_ignore=True)
    ).run()


@dramatiq.actor(periodic=cron("@daily"))
def run_updates_daily() -> None:  # pragma: no cover
    (
        cleanup_subscriptions.message_with_options(pipe_ignore=True)
        | update_cve_data.message_with_options(pipe_ignore=True)
        | update_cpe_data.message_with_options(pipe_ignore=True)
        | update_cpe_match_data.message_with_options(pipe_ignore=True)
        | update_iut_data.message_with_options(pipe_ignore=True)
        | update_mip_data.message_with_options(pipe_ignore=True)
    ).run()
