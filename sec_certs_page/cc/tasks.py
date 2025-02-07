import logging
import os
import subprocess
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

import sentry_sdk
from dramatiq import pipeline
from flask import current_app
from sec_certs.dataset.auxiliary_dataset_handling import CCMaintenanceUpdateDatasetHandler, CCSchemeDatasetHandler
from sec_certs.dataset.cc import CCDataset
from sec_certs.utils.helpers import get_sha256_filepath

from .. import mongo, runtime_config
from ..common.diffs import DiffRenderer
from ..common.sentry import suppress_child_spans
from ..common.tasks import Archiver, Indexer, Notifier, Updater, actor
from . import cc_categories

logger = logging.getLogger(__name__)


class CCMixin:  # pragma: no cover
    def __init__(self):
        self.collection = "cc"
        self.diff_collection = "cc_diff"
        self.log_collection = "cc_log"
        self.skip_update = runtime_config["CC_SKIP_UPDATE"]
        self.dset_class = CCDataset
        self.dataset_path = current_app.config["DATASET_PATH_CC_DIR"]
        self.cert_schema = "cc"


class CCRenderer(DiffRenderer, CCMixin):  # pragma: no cover
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
            "protection_profiles": ("Protection Profiles of the certificate", True),
            "status": ("Status", False),
            "not_valid_after": ("Valid until date", False),
            "not_valid_before": ("Valid from date", False),
        }


class CCNotifier(Notifier, CCRenderer):
    pass


@actor("cc_notify", "cc_notify", "updates", timedelta(hours=1))
def notify(run_id):  # pragma: no cover
    notifier = CCNotifier()
    notifier.notify(run_id)


class CCIndexer(Indexer, CCMixin):  # pragma: no cover
    def create_document(self, dgst, document, cert, content):
        category_id = cc_categories[cert["category"]]["id"]
        return {
            "dgst": dgst,
            "name": cert["name"],
            "document_type": document,
            "cert_id": cert["heuristics"]["cert_id"],
            "cert_schema": self.cert_schema,
            "category": category_id,
            "status": cert["status"],
            "scheme": cert["scheme"],
            "content": content,
        }


@actor("cc_reindex_collection", "cc_reindex_collection", "updates", timedelta(hours=4))
def reindex_collection(to_reindex):  # pragma: no cover
    indexer = CCIndexer()
    indexer.reindex(to_reindex)


@actor("cc_reindex_all", "cc_reindex_all", "updates", timedelta(hours=1))
def reindex_all():  # pragma: no cover
    ids = list(map(lambda doc: doc["_id"], mongo.db.cc.find({}, {"_id": 1})))
    to_reindex = [(dgst, doc) for dgst in ids for doc in ("report", "target", "cert")]
    tasks = []
    for i in range(0, len(to_reindex), 1000):
        j = i + 1000
        tasks.append(reindex_collection.message_with_options(args=(to_reindex[i:j],), pipe_ignore=True))
    pipeline(tasks).run()


class CCArchiver(Archiver, CCMixin):  # pragma: no cover
    """
    CC Dataset
    ==========

    ├── auxiliary_datasets
    │   ├── cpe_dataset.json
    │   ├── cve_dataset.json
    │   ├── cpe_match.json
    │   ├── cc_scheme.json
    │   ├── protection_profiles
    │   │   ├── reports             (not present)
    │   │   │   ├── pdf
    │   │   │   └── txt
    │   │   ├── pps                 (not present)
    │   │   │   ├── pdf
    │   │   │   └── txt
    │   │   └── pp.json
    │   └── maintenances
    │       ├── certs               (not present)
    │       │   ├── reports
    │       │   │   ├── pdf
    │       │   │   └── txt
    │       │   └── targets
    │       │       ├── pdf
    │       │       └── txt
    │       └── maintenance_updates.json
    ├── certs
    │   ├── reports
    │   │   ├── pdf
    │   │   └── txt
    │   ├── targets
    │   │   ├── pdf
    │   │   └── txt
    │   └── certificates
    │       ├── pdf
    │       └── txt
    └── dataset.json
    """

    def archive(self, path, paths):
        with TemporaryDirectory() as tmpdir:
            logger.info(f"Archiving {path}")
            tmpdir = Path(tmpdir)

            auxdir = tmpdir / "auxiliary_datasets"
            auxdir.mkdir()
            os.symlink(paths["cve_path"], auxdir / "cve_dataset.json")
            os.symlink(paths["cpe_path"], auxdir / "cpe_dataset.json")
            os.symlink(paths["cpe_match_path"], auxdir / "cpe_match.json")
            os.symlink(paths["output_path_scheme"], auxdir / "cc_scheme.json")
            protection_profiles = auxdir / "protection_profiles"
            protection_profiles.mkdir()
            os.symlink(paths["output_path_pp"], protection_profiles / "pp.json")
            maintenances = auxdir / "maintenances"
            maintenances.mkdir()
            os.symlink(paths["output_path_mu"], maintenances / "maintenance_updates.json")

            os.symlink(paths["output_path"], tmpdir / "dataset.json")

            certs = tmpdir / "certs"
            certs.mkdir()
            os.symlink(paths["report"], certs / "reports")
            os.symlink(paths["target"], certs / "targets")
            os.symlink(paths["cert"], certs / "certificates")

            logger.info("Running tar...")
            subprocess.run(["tar", "-hczvf", path, "."], cwd=tmpdir)
            logger.info(f"Finished archiving {path}")


@actor("cc_archive", "cc_archive", "updates", timedelta(hours=4))
def archive(paths):  # pragma: no cover
    archiver = CCArchiver()
    archiver.archive(Path(current_app.instance_path) / current_app.config["DATASET_PATH_CC_ARCHIVE"], paths)


class CCUpdater(Updater, CCMixin):  # pragma: no cover
    def process(self, dset, paths):
        to_reindex = set()
        with sentry_sdk.start_span(op="cc.all", description="Get full CC dataset"):
            if not self.skip_update or not paths["output_path"].exists():
                with sentry_sdk.start_span(op="cc.get_certs", description="Get certs from web"), suppress_child_spans():
                    dset.get_certs_from_web(update_json=False)
                with (
                    sentry_sdk.start_span(
                        op="cc.auxiliary_datasets", description="Process auxiliary datasets (CVE, CPE, PP, MU, Scheme)"
                    ),
                    suppress_child_spans(),
                ):
                    dset.process_auxiliary_datasets(update_json=False)
                with (
                    sentry_sdk.start_span(op="cc.download_artifacts", description="Download artifacts"),
                    suppress_child_spans(),
                ):
                    dset.download_all_artifacts(update_json=False)
                with sentry_sdk.start_span(op="cc.convert_pdfs", description="Convert pdfs"), suppress_child_spans():
                    dset.convert_all_pdfs(update_json=False)
                with sentry_sdk.start_span(op="cc.analyze", description="Analyze certificates"), suppress_child_spans():
                    dset.analyze_certificates(update_json=False)
                with sentry_sdk.start_span(op="cc.write_json", description="Write JSON"), suppress_child_spans():
                    dset.to_json(paths["output_path"])
                    dset.aux_handlers[CCSchemeDatasetHandler].dset.to_json(paths["output_path_scheme"])
                    dset.aux_handlers[CCMaintenanceUpdateDatasetHandler].dset.to_json(paths["output_path_mu"])

            with sentry_sdk.start_span(op="cc.move", description="Move files"), suppress_child_spans():
                for cert in dset:
                    if cert.state.report.pdf_path and cert.state.report.pdf_path.exists():
                        dst = paths["report_pdf"] / f"{cert.dgst}.pdf"
                        if not dst.exists() or get_sha256_filepath(dst) != cert.state.report.pdf_hash:
                            cert.state.report.pdf_path.replace(dst)
                    if cert.state.report.txt_path and cert.state.report.txt_path.exists():
                        dst = paths["report_txt"] / f"{cert.dgst}.txt"
                        if not dst.exists() or get_sha256_filepath(dst) != cert.state.report.txt_hash:
                            cert.state.report.txt_path.replace(dst)
                            to_reindex.add((cert.dgst, "report"))
                    if cert.state.st.pdf_path and cert.state.st.pdf_path.exists():
                        dst = paths["target_pdf"] / f"{cert.dgst}.pdf"
                        if not dst.exists() or get_sha256_filepath(dst) != cert.state.st.pdf_hash:
                            cert.state.st.pdf_path.replace(dst)
                    if cert.state.st.txt_path and cert.state.st.txt_path.exists():
                        dst = paths["target_txt"] / f"{cert.dgst}.txt"
                        if not dst.exists() or get_sha256_filepath(dst) != cert.state.st.txt_hash:
                            cert.state.st.txt_path.replace(dst)
                            to_reindex.add((cert.dgst, "target"))
                    if cert.state.cert.pdf_path and cert.state.cert.pdf_path.exists():
                        dst = paths["cert_pdf"] / f"{cert.dgst}.pdf"
                        if not dst.exists() or get_sha256_filepath(dst) != cert.state.cert.pdf_hash:
                            cert.state.cert.pdf_path.replace(dst)
                    if cert.state.cert.txt_path and cert.state.cert.txt_path.exists():
                        dst = paths["cert_txt"] / f"{cert.dgst}.txt"
                        if not dst.exists() or get_sha256_filepath(dst) != cert.state.cert.txt_hash:
                            cert.state.cert.txt_path.replace(dst)
                            to_reindex.add((cert.dgst, "cert"))
            with sentry_sdk.start_span(op="cc.old_map", description="Update old digest map"), suppress_child_spans():
                for cert in dset:
                    if hasattr(cert, "old_dgst"):
                        mongo.db.cc_old.replace_one(
                            {"_id": cert.old_dgst}, {"_id": cert.old_dgst, "hashid": cert.dgst}, upsert=True
                        )
                    if hasattr(cert, "older_dgst"):
                        mongo.db.cc_old.replace_one(
                            {"_id": cert.older_dgst}, {"_id": cert.older_dgst, "hashid": cert.dgst}, upsert=True
                        )
        return to_reindex

    def dataset_state(self, dset):
        return dset.state.to_dict()

    def notify(self, run_id):
        notify.send(str(run_id))

    def reindex(self, to_reindex):
        reindex_collection.send(list(to_reindex))

    def archive(self, paths):
        archive.send(paths)


@actor("cc_update", "cc_update", "updates", timedelta(hours=16))
def update_data():  # pragma: no cover
    updater = CCUpdater()
    updater.update()
