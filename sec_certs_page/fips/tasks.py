import sentry_sdk
from celery.utils.log import get_task_logger
from flask import current_app
from sec_certs.dataset.fips import FIPSDataset
from sec_certs.sample.fips_iut import IUTSnapshot
from sec_certs.sample.fips_mip import MIPSnapshot

from .. import celery, mongo
from ..common.objformats import ObjFormat
from ..common.tasks import Indexer, Updater, no_simultaneous_execution
from . import fips_types

logger = get_task_logger(__name__)


@celery.task(ignore_result=True)
def notify(run_id):  # pragma: no cover
    # run = mongo.db.fips_log.find_one({"_id": run_id})
    # diffs = mongo.db.fips_diff.find({"run_id": run_id})
    pass


@celery.task(ignore_result=True)
def update_iut_data():  # pragma: no cover
    snapshot = IUTSnapshot.from_web()
    snap_data = ObjFormat(snapshot).to_raw_format().to_working_format().to_storage_format().get()
    mongo.db.fips_iut.insert_one(snap_data)


@celery.task(ignore_result=True)
def update_mip_data():  # pragma: no cover
    snapshot = MIPSnapshot.from_web()
    snap_data = ObjFormat(snapshot).to_raw_format().to_working_format().to_storage_format().get()
    mongo.db.fips_mip.insert_one(snap_data)


class FIPSIndexer(Indexer):  # pragma: no cover
    def __init__(self):
        self.dataset_path = current_app.config["DATASET_PATH_FIPS_DIR"]
        self.cert_schema = "fips"

    def create_document(self, dgst, document, cert, content):
        category_id = fips_types[cert["web_scan"]["module_type"]]["id"]
        return {
            "dgst": dgst,
            "name": cert["web_scan"]["module_name"],
            "document_type": document,
            "cert_schema": self.cert_schema,
            "category": category_id,
            "status": cert["web_scan"]["status"],
            "content": content,
        }


@celery.task(ignore_result=True)
@no_simultaneous_execution("reindex_collection")
def reindex_collection(to_reindex):  # pragma: no cover
    indexer = FIPSIndexer()
    indexer.reindex(to_reindex)


class FIPSUpdater(Updater):  # pragma: no cover
    def __init__(self):
        self.collection = "fips"
        self.diff_collection = "fips_diff"
        self.log_collection = "fips_log"
        self.skip_update = current_app.config["FIPS_SKIP_UPDATE"]
        self.dset_class = FIPSDataset

    def process(self, dset, paths):
        to_reindex = set()
        with sentry_sdk.start_span(op="fips.all", description="Get full FIPS dataset"):
            if not self.skip_update or not paths["output_path"].exists():
                with sentry_sdk.start_span(op="fips.get_certs", description="Get certs from web"):
                    dset.get_certs_from_web(update_json=False)
                with sentry_sdk.start_span(op="fips.convert_pdfs", description="Convert pdfs"):
                    dset.convert_all_pdfs(update_json=False)
                with sentry_sdk.start_span(op="fips.scan_pdfs", description="Scan pdfs"):
                    dset.pdf_scan(update_json=False)
                with sentry_sdk.start_span(op="fips.tables", description="Extract tables"):
                    dset.extract_certs_from_tables(high_precision=True, update_json=False)
                with sentry_sdk.start_span(op="fips.finalize_results", description="Finalize results"):
                    dset.finalize_results(update_json=False)
                with sentry_sdk.start_span(op="fips.write_json", description="Write JSON"):
                    dset.to_json(paths["output_path"])

            with sentry_sdk.start_span(op="fips.move", description="Move files"):
                for cert in dset:
                    if cert.state.sp_path:
                        pdf_path = cert.state.sp_path
                        if pdf_path.exists():
                            pdf_dst = paths["target_pdf"] / f"{cert.dgst}.pdf"
                            if not pdf_dst.exists() or pdf_dst.stat().st_size < pdf_path.stat().st_size:
                                pdf_path.replace(pdf_dst)
                        txt_path = pdf_path.with_suffix(".pdf.txt")
                        if txt_path.exists():
                            txt_dst = paths["target_txt"] / f"{cert.dgst}.txt"
                            if not txt_dst.exists() or txt_dst.stat().st_size < txt_path.stat().st_size:
                                txt_path.replace(txt_dst)
                                to_reindex.add((cert.dgst, "target"))
        return to_reindex

    def dataset_state(self, dset):
        return None

    def notify(self, run_id):
        notify.delay(str(run_id))

    def reindex(self, to_reindex):
        reindex_collection.delay(list(to_reindex))


@celery.task(ignore_result=True)
def update_data():  # pragma: no cover
    updater = FIPSUpdater()
    updater.update()
