import sentry_sdk
from celery.utils.log import get_task_logger
from flask import current_app
from sec_certs.dataset.common_criteria import CCDataset

from .. import celery
from ..common.diffs import DiffRenderer
from ..common.tasks import Indexer, Notifier, Updater, no_simultaneous_execution
from . import cc_categories

logger = get_task_logger(__name__)


class CCMixin:
    def __init__(self):
        self.collection = "cc"
        self.diff_collection = "cc_diff"
        self.log_collection = "cc_log"
        self.skip_update = current_app.config["CC_SKIP_UPDATE"]
        self.dset_class = CCDataset
        self.cert_schema = "cc"


class CCRenderer(DiffRenderer, CCMixin):
    def __init__(self):
        super().__init__()
        self.templates = {
            "new": "cc/notifications/diff_new.html.jinja2",
            "change": "cc/notifications/diff_change.html.jinja2",
            "remove": "cc/notifications/diff_remove.html.jinja2",
            "back": "cc/notifications/diff_back.html.jinja2",
        }
        self.k2map = {
            "pdf_data": ("PDF extraction data", False),
            "state": ("state of the certificate object", False),
            "heuristics": ("computed heuristics", True),
            "maintenance_updates": ("Maintenance Updates of the certificate", True),
            "protection_profiles": ("Protection profiles of the certificate", True),
            "status": ("Status", False),
            "not_valid_after": ("Valid until date", False),
            "not_valid_before": ("Valid from date", False),
        }


class CCNotifier(Notifier, CCRenderer):
    pass


@celery.task(ignore_result=True)
def notify(run_id):
    notifier = CCNotifier()
    notifier.notify(run_id)


class CCIndexer(Indexer, CCMixin):  # pragma: no cover
    def create_document(self, dgst, document, cert, content):
        category_id = cc_categories[cert["category"]]["id"]
        return {
            "dgst": dgst,
            "name": cert["name"],
            "document_type": document,
            "cert_schema": self.cert_schema,
            "category": category_id,
            "status": cert["status"],
            "content": content,
        }


@celery.task(ignore_result=True)
@no_simultaneous_execution("reindex_collection")
def reindex_collection(to_reindex):  # pragma: no cover
    indexer = CCIndexer()
    indexer.reindex(to_reindex)


class CCUpdater(Updater, CCMixin):  # pragma: no cover
    def process(self, dset, paths):
        to_reindex = set()
        with sentry_sdk.start_span(op="cc.all", description="Get full CC dataset"):
            if not self.skip_update or not paths["output_path"].exists():
                with sentry_sdk.start_span(op="cc.get_certs", description="Get certs from web"):
                    dset.get_certs_from_web(update_json=False)
                with sentry_sdk.start_span(op="cc.download_pdfs", description="Download pdfs"):
                    dset.download_all_pdfs(update_json=False)
                with sentry_sdk.start_span(op="cc.convert_pdfs", description="Convert pdfs"):
                    dset.convert_all_pdfs(update_json=False)
                with sentry_sdk.start_span(op="cc.analyze", description="Analyze certificates"):
                    dset.analyze_certificates(update_json=False)
                with sentry_sdk.start_span(op="cc.protection_profiles", description="Process protection profiles"):
                    dset.process_protection_profiles(update_json=False)
                with sentry_sdk.start_span(op="cc.maintenance_updates", description="Process maintenance updates"):
                    dset.process_maintenance_updates()
                with sentry_sdk.start_span(op="cc.protection_profiles", description="Process protection profiles"):
                    dset.process_protection_profiles()
                with sentry_sdk.start_span(op="cc.write_json", description="Write JSON"):
                    dset.to_json(paths["output_path"])

            with sentry_sdk.start_span(op="cc.move", description="Move files"):
                for cert in dset:
                    if cert.state.report_pdf_path and cert.state.report_pdf_path.exists():
                        dst = paths["report_pdf"] / f"{cert.dgst}.pdf"
                        if not dst.exists() or dst.stat().st_size < cert.state.report_pdf_path.stat().st_size:
                            cert.state.report_pdf_path.replace(dst)
                    if cert.state.report_txt_path and cert.state.report_txt_path.exists():
                        dst = paths["report_txt"] / f"{cert.dgst}.txt"
                        if not dst.exists() or dst.stat().st_size < cert.state.report_txt_path.stat().st_size:
                            cert.state.report_txt_path.replace(dst)
                            to_reindex.add((cert.dgst, "report"))
                    if cert.state.st_pdf_path and cert.state.st_pdf_path.exists():
                        dst = paths["target_pdf"] / f"{cert.dgst}.pdf"
                        if not dst.exists() or dst.stat().st_size < cert.state.st_pdf_path.stat().st_size:
                            cert.state.st_pdf_path.replace(dst)
                    if cert.state.st_txt_path and cert.state.st_txt_path.exists():
                        dst = paths["target_txt"] / f"{cert.dgst}.txt"
                        if not dst.exists() or dst.stat().st_size < cert.state.st_txt_path.stat().st_size:
                            cert.state.st_txt_path.replace(dst)
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
    updater = CCUpdater()
    updater.update()
