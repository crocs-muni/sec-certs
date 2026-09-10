import logging
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from dramatiq import pipeline
from flask import current_app
from sec_certs.dataset.auxiliary_dataset_handling import CCSchemeDatasetHandler
from sec_certs.dataset.eucc import EUCCDataset
from tantivy import Document

from .. import mongo, runtime_config
from ..common.diffs import DiffRenderer
from ..common.tasks.archive import Archiver
from ..common.tasks.index import Indexer, add_keyword_paths
from ..common.tasks.notify import Notifier
from ..common.tasks.update import Updater
from ..common.tasks.utils import actor
from .index import eucc_index

logger = logging.getLogger(__name__)


class EUCCMixin:  # pragma: no cover
    def __init__(self):
        self.collection = "eucc"
        self.diff_collection = "eucc_diff"
        self.log_collection = "eucc_log"
        self.skip_update = runtime_config["EUCC_SKIP_UPDATE"]
        self.dset_class = EUCCDataset
        self.dataset_path = current_app.config["DATASET_PATH_EUCC_DIR"]
        self.cert_schema = "eucc"
        # Mapping from the page's document directories to the dataset's ones.
        self.dset_folders = {"report": "reports", "target": "targets", "cert": "certificates"}


class EUCCRenderer(DiffRenderer, EUCCMixin):  # pragma: no cover
    def __init__(self):
        super().__init__()
        self.templates = {
            "new": "eucc/notifications/diff_new.html.jinja2",
            "change": "eucc/notifications/diff_change.html.jinja2",
            "remove": "eucc/notifications/diff_remove.html.jinja2",
            "back": "eucc/notifications/diff_back.html.jinja2",
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


class EUCCNotifier(Notifier, EUCCRenderer):
    pass


@actor("eucc_notify", "eucc_notify", "updates", timedelta(hours=1))
def notify(run_id):  # pragma: no cover
    notifier = EUCCNotifier()
    notifier.notify(run_id)


class EUCCIndexer(Indexer, EUCCMixin):  # pragma: no cover
    doc_types = ["cert", "report", "target"]

    def __init__(self):
        super().__init__()
        self.index = eucc_index()

    def create_document(self, dgst, cert, content):
        doc = Document()
        doc.add_text("dgst", dgst)
        doc.add_text("scheme", cert["scheme"])
        doc.add_text("eal", cert["heuristics"].get("eal") or "")
        doc.add_text("status", cert["status"] or "")
        nvb = (cert.get("not_valid_before") or {}).get("_value")
        nva = (cert.get("not_valid_after") or {}).get("_value")
        if nvb:
            doc.add_date("not_valid_before", datetime.strptime(nvb, "%Y-%m-%d"))
        if nva:
            doc.add_date("not_valid_after", datetime.strptime(nva, "%Y-%m-%d"))
        doc.add_text("name", cert["name"])
        doc.add_text("cert_id", cert["cert_id"])
        doc.add_text("cert_id_tokenized", cert["cert_id"])
        pdf_data = cert.get("pdf_data")
        add_keyword_paths(doc, "keywords_cert", pdf_data.get("cert_keywords"))
        add_keyword_paths(doc, "keywords_report", pdf_data.get("report_keywords"))
        add_keyword_paths(doc, "keywords_target", pdf_data.get("st_keywords"))
        doc.add_text("body_cert", content["cert"])
        doc.add_text("body_target", content["target"])
        doc.add_text("body_report", content["report"])

        return doc


@actor("eucc_reindex_collection", "eucc_reindex_collection", "updates", timedelta(hours=4))
def reindex_collection(to_reindex):  # pragma: no cover
    indexer = EUCCIndexer()
    indexer.reindex(to_reindex)


@actor("eucc_reindex_all", "eucc_reindex_all", "updates", timedelta(hours=1))
def reindex_all():  # pragma: no cover
    ids = [doc["_id"] for doc in mongo.db.eucc.find({}, {"_id": 1})]
    to_reindex = list(ids)
    tasks = []
    for i in range(0, len(to_reindex), 1000):
        j = i + 1000
        tasks.append(reindex_collection.message_with_options(args=(to_reindex[i:j],), pipe_ignore=True))
    pipeline(tasks).run()


class EUCCArchiver(Archiver, EUCCMixin):  # pragma: no cover
    """
    EUCC Dataset
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


@actor("eucc_archive", "eucc_archive", "updates", timedelta(hours=4))
def archive(ids, paths):  # pragma: no cover
    archiver = EUCCArchiver()
    archiver.archive(ids, Path(current_app.instance_path) / current_app.config["DATASET_PATH_EUCC_ARCHIVE"], paths)


@actor("eucc_archive_all", "eucc_archive_all", "updates", timedelta(hours=1))
def archive_all():  # pragma: no cover
    ids = [doc["_id"] for doc in mongo.db.eucc.find({}, {"_id": 1})]
    updater = EUCCUpdater()
    paths = updater.make_dataset_paths()
    archive.send(ids, {name: str(path) for name, path in paths.items()})


class EUCCUpdater(Updater, EUCCMixin):  # pragma: no cover
    def write_auxiliary_json(self, dset, paths: dict[str, Path]) -> None:
        dset.aux_handlers[CCSchemeDatasetHandler].dset.to_json(paths["output_path_scheme"])

    def dataset_state(self, dset):
        return dset.state.to_dict()

    def notify(self, run_id):
        notify.send(str(run_id))

    def reindex(self, to_reindex):
        reindex_collection.send(list(to_reindex))

    def archive(self, ids, paths):
        archive.send(ids, paths)


@actor("eucc_update", "eucc_update", "updates", timedelta(hours=16))
def update_data():  # pragma: no cover
    updater = EUCCUpdater()
    updater.update()
