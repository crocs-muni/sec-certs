import logging
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from dramatiq import pipeline
from flask import current_app
from sec_certs.dataset.auxiliary_dataset_handling import CCMaintenanceUpdateDatasetHandler, CCSchemeDatasetHandler
from sec_certs.dataset.cc import CCDataset
from tantivy import Document

from .. import mongo, runtime_config
from ..common.diffs import DiffRenderer
from ..common.tasks.archive import Archiver
from ..common.tasks.index import Indexer, add_keyword_paths
from ..common.tasks.notify import Notifier
from ..common.tasks.update import Updater
from ..common.tasks.utils import actor
from .index import cc_index

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
        # Mapping from the page's document directories to the dataset's ones.
        self.dset_folders = {"report": "reports", "target": "targets", "cert": "certificates"}


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
    doc_types = ["cert", "report", "target"]

    def __init__(self):
        super().__init__()
        self.index = cc_index()

    def create_document(self, dgst, cert, content):
        doc = Document()
        doc.add_text("dgst", dgst)
        doc.add_text("scheme", cert["scheme"])
        doc.add_text("category", cert["category"])
        doc.add_text("eal", cert["heuristics"].get("eal") or "")
        doc.add_text("status", cert["status"])
        if cert["not_valid_before"]:
            doc.add_date("not_valid_before", datetime.fromisoformat(cert["not_valid_before"]["_value"]))
        if cert["not_valid_after"]:
            doc.add_date("not_valid_after", datetime.fromisoformat(cert["not_valid_after"]["_value"]))
        doc.add_text("name", cert["name"])
        doc.add_text("manufacturer", cert["manufacturer"] or "")
        cert_labs = cert["heuristics"]["cert_lab"]
        doc.add_text("cert_lab", cert_labs[0] if cert_labs else "")
        doc.add_text("cert_id", cert["heuristics"]["cert_id"] or "")
        doc.add_text("cert_id_tokenized", cert["heuristics"]["cert_id"] or "")
        pdf_data = cert.get("pdf_data")
        add_keyword_paths(doc, "keywords_cert", pdf_data.get("cert_keywords"))
        add_keyword_paths(doc, "keywords_report", pdf_data.get("report_keywords"))
        add_keyword_paths(doc, "keywords_target", pdf_data.get("st_keywords"))
        doc.add_text("body_cert", content["cert"])
        doc.add_text("body_target", content["target"])
        doc.add_text("body_report", content["report"])

        return doc


@actor("cc_reindex_collection", "cc_reindex_collection", "updates", timedelta(hours=4))
def reindex_collection(to_reindex):  # pragma: no cover
    indexer = CCIndexer()
    indexer.reindex(to_reindex)


@actor("cc_reindex_all", "cc_reindex_all", "updates", timedelta(hours=1))
def reindex_all():  # pragma: no cover
    ids = [doc["_id"] for doc in mongo.db.cc.find({}, {"_id": 1})]
    to_reindex = list(ids)
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
    │   │   └── dataset.json
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

    def archive(self, ids, path, paths):
        with TemporaryDirectory() as tmpdir:
            logger.info(f"Archiving {path}")
            tmpdir = Path(tmpdir)

            auxdir = tmpdir / "auxiliary_datasets"
            auxdir.mkdir()
            (auxdir / "cve_dataset.json").symlink_to(paths["cve_path"])
            (auxdir / "cpe_dataset.json").symlink_to(paths["cpe_path"])
            (auxdir / "cpe_match.json").symlink_to(paths["cpe_match_path"])
            (auxdir / "cc_scheme.json").symlink_to(paths["output_path_scheme"])
            protection_profiles = auxdir / "protection_profiles"
            protection_profiles.mkdir()
            (protection_profiles / "dataset.json").symlink_to(paths["output_path_pp"])
            maintenances = auxdir / "maintenances"
            maintenances.mkdir()
            (maintenances / "maintenance_updates.json").symlink_to(paths["output_path_mu"])

            (tmpdir / "dataset.json").symlink_to(paths["output_path"])

            certs = tmpdir / "certs"
            certs.mkdir()
            self.map_artifact_dir(ids, paths["report"], certs / "reports")
            self.map_artifact_dir(ids, paths["target"], certs / "targets")
            self.map_artifact_dir(ids, paths["cert"], certs / "certificates")

            logger.info("Running tar...")
            subprocess.run(["tar", "-hczvf", path, "."], cwd=tmpdir)
            logger.info(f"Finished archiving {path}")


@actor("cc_archive", "cc_archive", "updates", timedelta(hours=4))
def archive(ids, paths):  # pragma: no cover
    archiver = CCArchiver()
    archiver.archive(ids, Path(current_app.instance_path) / current_app.config["DATASET_PATH_CC_ARCHIVE"], paths)


@actor("cc_archive_all", "cc_archive_all", "updates", timedelta(hours=1))
def archive_all():  # pragma: no cover
    ids = [doc["_id"] for doc in mongo.db.cc.find({}, {"_id": 1})]
    updater = CCUpdater()
    paths = updater.make_dataset_paths()
    archive.send(ids, {name: str(path) for name, path in paths.items()})


class CCUpdater(Updater, CCMixin):  # pragma: no cover
    def write_auxiliary_json(self, dset, paths: dict[str, Path]) -> None:
        dset.aux_handlers[CCSchemeDatasetHandler].dset.to_json(paths["output_path_scheme"])
        dset.aux_handlers[CCMaintenanceUpdateDatasetHandler].dset.to_json(paths["output_path_mu"])

    def dataset_state(self, dset):
        return dset.state.to_dict()

    def notify(self, run_id):
        notify.send(str(run_id))

    def reindex(self, to_reindex):
        reindex_collection.send(list(to_reindex))

    def archive(self, ids, paths):
        archive.send(ids, paths)


@actor("cc_update", "cc_update", "updates", timedelta(hours=16))
def update_data():  # pragma: no cover
    updater = CCUpdater()
    updater.update()
