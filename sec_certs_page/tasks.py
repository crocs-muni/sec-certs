import logging
from logging import Logger
from pathlib import Path

import dramatiq
import sentry_sdk
from flask import current_app
from periodiq import cron
from pymongo import ReplaceOne
from sec_certs.dataset.cpe import CPEDataset
from sec_certs.dataset.cve import CVEDataset

from . import mongo
from .cc.tasks import update_data as update_cc_data
from .cc.tasks import update_scheme_data as update_cc_scheme_data
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

    logger.info("Getting CVEs.")
    with sentry_sdk.start_span(op="cve.get", description="Get CVEs."):
        cve_dset: CVEDataset = CVEDataset.from_web()
    logger.info(f"Got {len(cve_dset)} CVEs.")

    logger.info("Saving CVE dataset.")
    with sentry_sdk.start_span(op="cve.save", description="Save CVEs."):
        cve_dset.to_json(cve_path)

    logger.info("Inserting CVEs.")
    with sentry_sdk.start_span(op="cve.insert", description="Insert CVEs into DB."):
        cves = list(cve_dset)
        for i in range(0, len(cve_dset), 10000):
            chunk = []
            for cve in cves[i : i + 10000]:
                cve_data = ObjFormat(cve).to_raw_format().to_working_format().to_storage_format().get()
                cve_data["_id"] = cve.cve_id
                chunk.append(ReplaceOne({"_id": cve.cve_id}, cve_data, upsert=True))
            res = mongo.db.cve.bulk_write(chunk, ordered=False)
            res_vals = ", ".join(f"{k} = {v}" for k, v in res.bulk_api_result.items() if k != "upserted")
            logger.info(f"Inserted chunk: {res_vals}")


@dramatiq.actor(max_retries=0, actor_name="cpe_update")
@no_simultaneous_execution("cpe_update", abort=True, timeout=3600)
def update_cpe_data() -> None:  # pragma: no cover
    instance_path = Path(current_app.instance_path)
    cpe_path = instance_path / current_app.config["DATASET_PATH_CPE"]
    cve_path = instance_path / current_app.config["DATASET_PATH_CVE"]

    logger.info("Getting CPEs.")
    with sentry_sdk.start_span(op="cpe.get", description="Get CPEs."):
        cpe_dset: CPEDataset = CPEDataset.from_web(cpe_path)
    logger.info(f"Got {len(cpe_dset)} CPEs.")

    logger.info("Enhancing with CVE CPEs.")
    with sentry_sdk.start_span(op="cpe.enhance", description="Enhance CPEs."):
        cpe_dset.enhance_with_cpes_from_cve_dataset(cve_path)
    logger.info(f"Got {len(cpe_dset)} CPEs.")

    logger.info("Saving CPE dataset.")
    with sentry_sdk.start_span(op="cpe.save", description="Save CPEs."):
        cpe_dset.to_json()

    logger.info("Inserting CPEs.")
    with sentry_sdk.start_span(op="cpe.insert", description="Insert CPEs into DB."):
        cpes = list(cpe_dset)
        for i in range(0, len(cpe_dset), 10000):
            chunk = []
            for cpe in cpes[i : i + 10000]:
                cpe_data = ObjFormat(cpe).to_raw_format().to_working_format().to_storage_format().get()
                cpe_data["_id"] = cpe.uri
                chunk.append(ReplaceOne({"_id": cpe.uri}, cpe_data, upsert=True))
        res = mongo.db.cpe.bulk_write(chunk, ordered=False)
        res_vals = ", ".join(f"{k} = {v}" for k, v in res.bulk_api_result.items() if k != "upserted")
        logger.info(f"Inserted chunk: {res_vals}")


@dramatiq.actor(periodic=cron("@weekly"))
def run_updates_weekly() -> None:  # pragma: no cover
    (
        update_cc_data.message_with_options(pipe_ignore=True)
        | update_cc_scheme_data.message_with_options(pipe_ignore=True)
        | update_fips_data.message_with_options(pipe_ignore=True)
    ).run()


@dramatiq.actor(periodic=cron("@daily"))
def run_updates_daily() -> None:  # pragma: no cover
    (
        cleanup_subscriptions.message_with_options(pipe_ignore=True)
        | update_cve_data.message_with_options(pipe_ignore=True)
        | update_cpe_data.message_with_options(pipe_ignore=True)
        | update_iut_data.message_with_options(pipe_ignore=True)
        | update_mip_data.message_with_options(pipe_ignore=True)
    ).run()
