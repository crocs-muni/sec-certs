import logging
from datetime import datetime, timedelta

import dramatiq
import sentry_sdk
from bson.objectid import ObjectId
from flask import current_app
from sec_certs.dataset.cc import CCDataset, CCSchemeDataset
from sec_certs.utils.helpers import get_sha256_filepath

from .. import mongo
from ..common.diffs import DiffRenderer
from ..common.sentry import suppress_child_spans
from ..common.tasks import Indexer, Notifier, Updater, no_simultaneous_execution
from . import cc_categories

logger = logging.getLogger(__name__)


class CCMixin:
    def __init__(self):
        self.collection = "cc"
        self.diff_collection = "cc_diff"
        self.log_collection = "cc_log"
        self.skip_update = current_app.config["CC_SKIP_UPDATE"]
        self.dset_class = CCDataset
        self.dataset_path = current_app.config["DATASET_PATH_CC_DIR"]
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


@dramatiq.actor(max_retries=0)
@no_simultaneous_execution("cc_notify", abort=True)
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


@dramatiq.actor(max_retries=0)
@no_simultaneous_execution("reindex_collection")
def reindex_collection(to_reindex):  # pragma: no cover
    indexer = CCIndexer()
    indexer.reindex(to_reindex)


class CCUpdater(Updater, CCMixin):  # pragma: no cover
    def process(self, dset, paths):
        to_reindex = set()
        with sentry_sdk.start_span(op="cc.all", description="Get full CC dataset"):
            if not self.skip_update or not paths["output_path"].exists():
                with sentry_sdk.start_span(op="cc.get_certs", description="Get certs from web"), suppress_child_spans():
                    dset.get_certs_from_web(update_json=False)
                with sentry_sdk.start_span(
                    op="cc.auxiliary_datasets", description="Process auxiliary datasets (CVE, CPE, PP, MU)"
                ), suppress_child_spans():
                    dset.process_auxiliary_datasets(update_json=False)
                with sentry_sdk.start_span(
                    op="cc.download_artifacts", description="Download artifacts"
                ), suppress_child_spans():
                    dset.download_all_artifacts(update_json=False)
                with sentry_sdk.start_span(op="cc.convert_pdfs", description="Convert pdfs"), suppress_child_spans():
                    dset.convert_all_pdfs(update_json=False)
                with sentry_sdk.start_span(op="cc.analyze", description="Analyze certificates"), suppress_child_spans():
                    dset.analyze_certificates(update_json=False)
                with sentry_sdk.start_span(op="cc.write_json", description="Write JSON"), suppress_child_spans():
                    dset.to_json(paths["output_path"])
                    dset.auxiliary_datasets.mu_dset.to_json(paths["output_path_mu"])

            with sentry_sdk.start_span(op="cc.move", description="Move files"), suppress_child_spans():
                for cert in dset:
                    if cert.state.report_pdf_path and cert.state.report_pdf_path.exists():
                        dst = paths["report_pdf"] / f"{cert.dgst}.pdf"
                        if not dst.exists() or get_sha256_filepath(dst) != cert.state.report_pdf_hash:
                            cert.state.report_pdf_path.replace(dst)
                    if cert.state.report_txt_path and cert.state.report_txt_path.exists():
                        dst = paths["report_txt"] / f"{cert.dgst}.txt"
                        if not dst.exists() or get_sha256_filepath(dst) != cert.state.report_txt_hash:
                            cert.state.report_txt_path.replace(dst)
                            to_reindex.add((cert.dgst, "report"))
                    if cert.state.st_pdf_path and cert.state.st_pdf_path.exists():
                        dst = paths["target_pdf"] / f"{cert.dgst}.pdf"
                        if not dst.exists() or get_sha256_filepath(dst) != cert.state.st_pdf_hash:
                            cert.state.st_pdf_path.replace(dst)
                    if cert.state.st_txt_path and cert.state.st_txt_path.exists():
                        dst = paths["target_txt"] / f"{cert.dgst}.txt"
                        if not dst.exists() or get_sha256_filepath(dst) != cert.state.st_txt_hash:
                            cert.state.st_txt_path.replace(dst)
                            to_reindex.add((cert.dgst, "target"))
        return to_reindex

    def dataset_state(self, dset):
        return dset.state.to_dict()

    def notify(self, run_id):
        notify.send(str(run_id))

    def reindex(self, to_reindex):
        reindex_collection.send(list(to_reindex))


@dramatiq.actor(max_retries=0, time_limit=timedelta(hours=12).total_seconds() * 1000)
@no_simultaneous_execution("cc_update", abort=True, timeout=timedelta(hours=12).total_seconds())
def update_data():  # pragma: no cover
    updater = CCUpdater()
    updater.update()


@dramatiq.actor(max_retries=0)
@no_simultaneous_execution("cc_scheme_update", abort=True, timeout=3600 * 12)
def update_scheme_data():  # pragma: no cover
    schemes = {
        "AU": [{"type": "ineval", "method": CCSchemeDataset.get_australia_in_evaluation}],
        "CA": [
            {"type": "ineval", "method": CCSchemeDataset.get_canada_in_evaluation},
            {"type": "certified", "method": CCSchemeDataset.get_canada_certified},
        ],
        "FR": [{"type": "certified", "method": CCSchemeDataset.get_france_certified}],
        "DE": [{"type": "certified", "method": CCSchemeDataset.get_germany_certified}],
        "IN": [
            {"type": "certified", "method": CCSchemeDataset.get_india_certified},
            {"type": "archived", "method": CCSchemeDataset.get_india_archived},
        ],
        "IT": [
            {"type": "certified", "method": CCSchemeDataset.get_italy_certified},
            {"type": "ineval", "method": CCSchemeDataset.get_italy_in_evaluation},
        ],
        "JP": [
            {"type": "ineval", "method": CCSchemeDataset.get_japan_in_evaluation},
            {"type": "certified", "method": CCSchemeDataset.get_japan_certified},
            {"type": "archived", "method": CCSchemeDataset.get_japan_archived},
        ],
        "MY": [
            {"type": "certified", "method": CCSchemeDataset.get_malaysia_certified},
            {"type": "ineval", "method": CCSchemeDataset.get_malaysia_in_evaluation},
        ],
        "NL": [
            {"type": "certified", "method": CCSchemeDataset.get_netherlands_certified},
            {"type": "ineval", "method": CCSchemeDataset.get_netherlands_in_evaluation},
        ],
        "NO": [
            {"type": "certified", "method": CCSchemeDataset.get_norway_certified},
            {"type": "archived", "method": CCSchemeDataset.get_norway_archived},
        ],
        "KO": [
            {"type": "suspended", "method": CCSchemeDataset.get_korea_suspended},
            {"type": "certified", "method": CCSchemeDataset.get_korea_certified},
            {"type": "archived", "method": CCSchemeDataset.get_korea_archived},
        ],
        "SG": [
            {"type": "ineval", "method": CCSchemeDataset.get_singapore_in_evaluation},
            {"type": "certified", "method": CCSchemeDataset.get_singapore_certified},
            {"type": "archived", "method": CCSchemeDataset.get_singapore_archived},
        ],
        "ES": [{"type": "certified", "method": CCSchemeDataset.get_spain_certified}],
        "SE": [
            {"type": "ineval", "method": CCSchemeDataset.get_sweden_in_evaluation},
            {"type": "certified", "method": CCSchemeDataset.get_sweden_certified},
            {"type": "archived", "method": CCSchemeDataset.get_sweden_archived},
        ],
        "TR": [{"type": "certified", "method": CCSchemeDataset.get_turkey_certified}],
        "US": [
            {"type": "ineval", "method": CCSchemeDataset.get_usa_in_evaluation},
            {"type": "certified", "method": CCSchemeDataset.get_usa_certified},
            {"type": "archived", "method": CCSchemeDataset.get_usa_archived},
        ],
    }

    run_id = ObjectId()

    for scheme, sources in schemes.items():
        for source in sources:
            source_type = source["type"]
            source_method = source["method"]
            start = datetime.now()
            try:
                res = source_method()
            except Exception as e:
                logger.warning(f"Error during {scheme} download of {source_type}: {e}")
                continue
            end = datetime.now()
            logger.info(f"Finished scheme download for {scheme} {source_type}.")

            mongo.db.cc_scheme.insert_one(
                {
                    "run_id": run_id,
                    "scheme": scheme,
                    "type": source_type,
                    "start_time": start,
                    "end_time": end,
                    "results": res,
                }
            )
