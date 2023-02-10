import sentry_sdk
from celery.utils.log import get_task_logger
from flask import current_app
from sec_certs.dataset.fips import FIPSDataset
from sec_certs.sample.fips_iut import IUTSnapshot
from sec_certs.sample.fips_mip import MIPSnapshot
from sec_certs.utils.helpers import get_sha256_filepath

from .. import celery, mongo
from ..common.diffs import DiffRenderer
from ..common.objformats import ObjFormat
from ..common.tasks import Indexer, Notifier, Updater, no_simultaneous_execution
from . import fips_types

logger = get_task_logger(__name__)


class FIPSMixin:
    def __init__(self):
        self.collection = "fips"
        self.diff_collection = "fips_diff"
        self.log_collection = "fips_log"
        self.skip_update = current_app.config["FIPS_SKIP_UPDATE"]
        self.dset_class = FIPSDataset
        self.dataset_path = current_app.config["DATASET_PATH_FIPS_DIR"]
        self.cert_schema = "fips"
        self.lock_name = "fips_update"


class FIPSRenderer(DiffRenderer, FIPSMixin):
    def __init__(self):
        super().__init__()
        self.templates = {
            "new": "fips/notifications/diff_new.html.jinja2",
            "change": "fips/notifications/diff_change.html.jinja2",
            "remove": "fips/notifications/diff_remove.html.jinja2",
            "back": "fips/notifications/diff_back.html.jinja2",
        }
        self.k2map = {
            "web_data": ("web extraction data", False),
            "pdf_data": ("PDF extraction data", False),
            "heuristics": ("computed heuristics", True),
        }


class FIPSNotifier(Notifier, FIPSRenderer):
    pass


@celery.task(ignore_result=True)
def notify(run_id):  # pragma: no cover
    notifier = FIPSNotifier()
    notifier.notify(run_id)


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


class FIPSIndexer(Indexer, FIPSMixin):  # pragma: no cover
    def create_document(self, dgst, document, cert, content):
        category_id = fips_types[cert["web_data"]["module_type"]]["id"]
        return {
            "dgst": dgst,
            "name": cert["web_data"]["module_name"],
            "document_type": document,
            "cert_schema": self.cert_schema,
            "category": category_id,
            "status": cert["web_data"]["status"],
            "content": content,
        }


@celery.task(ignore_result=True)
@no_simultaneous_execution("reindex_collection")
def reindex_collection(to_reindex):  # pragma: no cover
    indexer = FIPSIndexer()
    indexer.reindex(to_reindex)


class FIPSUpdater(Updater, FIPSMixin):  # pragma: no cover
    def process(self, dset: FIPSDataset, paths):
        to_reindex = set()
        with sentry_sdk.start_span(op="fips.all", description="Get full FIPS dataset"):
            if not self.skip_update or not paths["output_path"].exists():
                with sentry_sdk.start_span(op="fips.get_certs", description="Get certs from web"):
                    dset.get_certs_from_web(update_json=False)
                with sentry_sdk.start_span(
                    op="fips.auxiliary_datasets", description="Process auxiliary datasets (CVE, CPE, Algo)"
                ):
                    dset.process_auxiliary_datasets(update_json=False)
                with sentry_sdk.start_span(op="fips.download_artifacts", description="Download artifacts"):
                    dset.download_all_artifacts(update_json=False)
                with sentry_sdk.start_span(op="fips.convert_pdfs", description="Convert pdfs"):
                    dset.convert_all_pdfs(update_json=False)
                with sentry_sdk.start_span(op="fips.analyze", description="Analyze certificates"):
                    dset.analyze_certificates(update_json=False)
                with sentry_sdk.start_span(op="fips.write_json", description="Write JSON"):
                    dset.to_json(paths["output_path"])

            with sentry_sdk.start_span(op="fips.move", description="Move files"):
                for cert in dset:
                    if cert.state.policy_pdf_path and cert.state.policy_pdf_path.exists():
                        dst = paths["target_pdf"] / f"{cert.dgst}.pdf"
                        if not dst.exists() or get_sha256_filepath(dst) != cert.state.policy_pdf_hash:
                            cert.state.policy_pdf_path.replace(dst)
                    if cert.state.policy_txt_path and cert.state.policy_txt_path.exists():
                        dst = paths["target_txt"] / f"{cert.dgst}.txt"
                        if not dst.exists() or get_sha256_filepath(dst) != cert.state.policy_txt_hash:
                            cert.state.policy_txt_path.replace(dst)
                            to_reindex.add((cert.dgst, "target"))
        return to_reindex

    def dataset_state(self, dset):
        return dset.state.to_dict()

    def notify(self, run_id):
        notify.delay(str(run_id))

    def reindex(self, to_reindex):
        reindex_collection.delay(list(to_reindex))


@celery.task(ignore_result=True)
def update_data():  # pragma: no cover
    updater = FIPSUpdater()
    updater.update()
