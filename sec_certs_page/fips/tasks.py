from pathlib import Path
from celery.utils.log import get_task_logger

from .. import celery
import sentry_sdk
from sec_certs.dataset.fips import FIPSDataset
from flask import current_app


logging = get_task_logger(__name__)


@celery.task(ignore_result=True)
def update_data():
    instance_path = Path(current_app.instance_path)
    dset_path = instance_path / current_app.config["DATASET_PATH_FIPS"]
    output_path = instance_path / current_app.config["DATASET_PATH_FIPS_OUT"]
    dset = FIPSDataset({}, dset_path, "dataset", "Description")
    try:
        with sentry_sdk.start_span(op="fips.all", description="Get full FIPS dataset"):
            with sentry_sdk.start_span(op="fips.get_certs", description="Get certs from web"):
                dset.get_certs_from_web()
            with sentry_sdk.start_span(op="fips.convert_pdfs", description="Convert pdfs"):
                dset.convert_all_pdfs()
            with sentry_sdk.start_span(op="cc.scan_pdfs", description="Scan pdfs"):
                dset.pdf_scan()
            with sentry_sdk.start_span(op="cc.tables", description="Extract tables"):
                dset.extract_certs_from_tables(high_precision=True)
            with sentry_sdk.start_span(op="cc.finalize_results", description="Finalize results"):
                dset.finalize_results()
            # TODO: And then somehow import the results of analysis into the DB while tracking differences.
            dset.to_json(output_path)
    except Exception as e:
        logging.error(str(e))

