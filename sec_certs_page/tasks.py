from pathlib import Path

from celery import chain
from flask import current_app
from sec_certs.dataset.cpe import CPEDataset
from sec_certs.dataset.cve import CVEDataset

from . import celery
from .cc.tasks import update_data as update_cc_data
from .fips.tasks import update_data as update_fips_data


@celery.task(ignore_result=True)
def update_cve_data():
    cve_dset: CVEDataset = CVEDataset.from_web()
    instance_path = Path(current_app.instance_path)
    cve_dset.to_json(instance_path / current_app.config["DATASET_PATH_CVE"])


@celery.task(ignore_result=True)
def update_cpe_data():
    instance_path = Path(current_app.instance_path)
    cpe_path = instance_path / current_app.config["DATASET_PATH_CPE"]
    cpe_dset: CPEDataset = CPEDataset.from_web(cpe_path)
    cpe_dset.to_json()


@celery.task(ignore_result=True)
def run_updates():
    chain(update_cve_data.si(), update_cpe_data.si(), update_cc_data.si(), update_fips_data.si()).delay()
