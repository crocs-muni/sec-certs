from pathlib import Path

from celery import chain
from celery.utils.log import get_task_logger
from flask import current_app
from sec_certs.dataset.cpe import CPEDataset
from sec_certs.dataset.cve import CVEDataset

from . import celery, mongo
from .cc.tasks import update_data as update_cc_data
from .fips.tasks import update_data as update_fips_data
from .utils import dictify_serializable

logger = get_task_logger(__name__)


@celery.task(ignore_result=True)
def update_cve_data():
    instance_path = Path(current_app.instance_path)
    cve_path = instance_path / current_app.config["DATASET_PATH_CVE"]

    cve_dset: CVEDataset = CVEDataset.from_web()
    logger.info(f"Got {len(cve_dset)} CVEs.")
    logger.info("Saving CVE dataset.")
    cve_dset.to_json(cve_path)

    logger.info("Inserting CVEs.")

    for cve in cve_dset:
        cve_data = dictify_serializable(cve, "cve_id")
        mongo.db.cve.replace_one({"_id": cve.cve_id}, cve_data, upsert=True)


@celery.task(ignore_result=True)
def update_cpe_data():
    instance_path = Path(current_app.instance_path)
    cpe_path = instance_path / current_app.config["DATASET_PATH_CPE"]

    cpe_dset: CPEDataset = CPEDataset.from_web(cpe_path)
    logger.info(f"Got {len(cpe_dset)} CPEs.")
    logger.info("Saving CPE dataset.")
    cpe_dset.to_json()

    logger.info("Inserting CPEs.")

    for cpe in cpe_dset:
        cpe_data = dictify_serializable(cpe, "uri")
        mongo.db.cpe.replace_one({"_id": cpe.uri}, cpe_data, upsert=True)


@celery.task(ignore_result=True)
def run_updates():
    chain(update_cve_data.si(), update_cpe_data.si(), update_cc_data.si(), update_fips_data.si()).delay()
