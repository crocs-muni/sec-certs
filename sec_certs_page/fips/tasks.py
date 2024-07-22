from datetime import timedelta
from pathlib import Path

import dramatiq
import sentry_sdk
from dramatiq.logging import get_logger
from flask import current_app
from sec_certs.dataset.fips import FIPSDataset
from sec_certs.sample.fips_iut import IUTSnapshot
from sec_certs.sample.fips_mip import MIPSnapshot
from sec_certs.utils.helpers import get_sha256_filepath

from .. import mongo
from ..common.diffs import DiffRenderer
from ..common.objformats import ObjFormat
from ..common.sentry import suppress_child_spans
from ..common.tasks import Archiver, Indexer, Notifier, Updater, no_simultaneous_execution
from . import fips_types

logger = get_logger(__name__)


class FIPSMixin:
    def __init__(self):
        self.collection = "fips"
        self.diff_collection = "fips_diff"
        self.log_collection = "fips_log"
        self.skip_update = current_app.config["FIPS_SKIP_UPDATE"]
        self.dset_class = FIPSDataset
        self.dataset_path = current_app.config["DATASET_PATH_FIPS_DIR"]
        self.cert_schema = "fips"


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


@dramatiq.actor(max_retries=0, actor_name="fips_notify")
@no_simultaneous_execution("fips_notify", abort=True)
def notify(run_id):  # pragma: no cover
    notifier = FIPSNotifier()
    notifier.notify(run_id)


@dramatiq.actor(max_retries=0, actor_name="fips_iut_update")
@no_simultaneous_execution("fips_iut_update", abort=True)
def update_iut_data():  # pragma: no cover
    snapshot = IUTSnapshot.from_web()
    snap_data = ObjFormat(snapshot).to_raw_format().to_working_format().to_storage_format().get()
    mongo.db.fips_iut.insert_one(snap_data)


@dramatiq.actor(max_retries=0, actor_name="fips_mip_update")
@no_simultaneous_execution("fips_mip_update", abort=True)
def update_mip_data():  # pragma: no cover
    snapshot = MIPSnapshot.from_web()
    snap_data = ObjFormat(snapshot).to_raw_format().to_working_format().to_storage_format().get()
    mongo.db.fips_mip.insert_one(snap_data)


class FIPSIndexer(Indexer, FIPSMixin):  # pragma: no cover
    def create_document(self, dgst, document, cert, content):
        mod_type = cert["web_data"]["module_type"]
        try:
            category_id = fips_types[mod_type]["id"]
        except KeyError:
            logger.error(f"Could not find FIPS type: {mod_type}.")
            category_id = None
        return {
            "dgst": dgst,
            "name": cert["web_data"]["module_name"],
            "document_type": document,
            "cert_schema": self.cert_schema,
            "category": category_id,
            "status": cert["web_data"]["status"],
            "content": content,
        }


@dramatiq.actor(max_retries=0, actor_name="fips_reindex_collection")
@no_simultaneous_execution("reindex_collection")
def reindex_collection(to_reindex):  # pragma: no cover
    indexer = FIPSIndexer()
    indexer.reindex(to_reindex)


class FIPSArchiver(Archiver, FIPSMixin):  # pragma: no cover
    def archive_custom(self, paths, tmpdir):
        pass


@dramatiq.actor(max_retries=0, time_limit=timedelta(hours=1).total_seconds() * 1000, actor_name="fips_archive")
@no_simultaneous_execution("fips_archive", timeout=timedelta(hours=1).total_seconds())
def archive(paths):  # pragma: no cover
    archiver = FIPSArchiver()
    archiver.archive(Path(current_app.instance_path) / current_app.config["DATASET_PATH_FIPS_ARCHIVE"], paths)


class FIPSUpdater(Updater, FIPSMixin):  # pragma: no cover
    def process(self, dset: FIPSDataset, paths):
        to_reindex = set()
        with sentry_sdk.start_span(op="fips.all", description="Get full FIPS dataset"):
            if not self.skip_update or not paths["output_path"].exists():
                with sentry_sdk.start_span(
                    op="fips.get_certs", description="Get certs from web"
                ), suppress_child_spans():
                    dset.get_certs_from_web(update_json=False)
                with sentry_sdk.start_span(
                    op="fips.auxiliary_datasets", description="Process auxiliary datasets (CVE, CPE, Algo)"
                ), suppress_child_spans():
                    dset.process_auxiliary_datasets(update_json=False)
                with sentry_sdk.start_span(
                    op="fips.download_artifacts", description="Download artifacts"
                ), suppress_child_spans():
                    dset.download_all_artifacts(update_json=False)
                with sentry_sdk.start_span(op="fips.convert_pdfs", description="Convert pdfs"), suppress_child_spans():
                    dset.convert_all_pdfs(update_json=False)
                with sentry_sdk.start_span(
                    op="fips.analyze", description="Analyze certificates"
                ), suppress_child_spans():
                    dset.analyze_certificates(update_json=False)
                with sentry_sdk.start_span(op="fips.write_json", description="Write JSON"), suppress_child_spans():
                    dset.to_json(paths["output_path"])

            with sentry_sdk.start_span(op="fips.move", description="Move files"), suppress_child_spans():
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
        notify.send(str(run_id))

    def reindex(self, to_reindex):
        reindex_collection.send(list(to_reindex))

    def archive(self, paths):
        archive.send(paths)


@dramatiq.actor(max_retries=0, time_limit=timedelta(hours=16).total_seconds() * 1000, actor_name="fips_update")
@no_simultaneous_execution("fips_update", abort=True, timeout=timedelta(hours=17).total_seconds())
def update_data():  # pragma: no cover
    updater = FIPSUpdater()
    updater.update()
