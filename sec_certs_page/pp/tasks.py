import logging
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from dramatiq import pipeline
from flask import current_app
from sec_certs.dataset import ProtectionProfileDataset
from tantivy import Document

from .. import mongo, runtime_config
from ..common.diffs import DiffRenderer
from ..common.tasks.archive import Archiver
from ..common.tasks.index import Indexer, add_keyword_paths
from ..common.tasks.update import Updater
from ..common.tasks.utils import actor
from .index import pp_index

logger = logging.getLogger(__name__)


class PPMixin:  # pragma: no cover
    def __init__(self):
        self.collection = "pp"
        self.diff_collection = "pp_diff"
        self.log_collection = "pp_log"
        self.skip_update = runtime_config["PP_SKIP_UPDATE"]
        self.dset_class = ProtectionProfileDataset
        self.dataset_path = current_app.config["DATASET_PATH_PP_DIR"]
        self.cert_schema = "pp"
        # Mapping from the page's document directories to the dataset's ones.
        self.dset_folders = {"report": "reports", "profile": "pps"}


class PPRenderer(DiffRenderer, PPMixin):  # pragma: no cover
    def __init__(self):
        super().__init__()
        self.templates = {
            "new": "pp/notifications/diff_new.html.jinja2",
            "change": "pp/notifications/diff_change.html.jinja2",
            "remove": "pp/notifications/diff_remove.html.jinja2",
            "back": "pp/notifications/diff_back.html.jinja2",
        }
        self.k2map = {
            "web_data": ("CC portal data", False),
            "pdf_data": ("PDF extraction data", False),
            "state": ("state of the protection profile object", False),
            "heuristics": ("computed heuristics", True),
            "scheme_metadata": ("national scheme metadata", False),
        }


class PPIndexer(Indexer, PPMixin):  # pragma: no cover
    doc_types = ["report", "profile"]

    def __init__(self):
        super().__init__()
        self.index = pp_index()

    def create_document(self, dgst, cert, content):
        web_data = cert["web_data"]
        doc = Document()
        doc.add_text("dgst", dgst)
        doc.add_text("category", web_data["category"])
        doc.add_text("status", web_data["status"])
        doc.add_text("scheme", web_data["scheme"] or "")
        doc.add_text("name", web_data["name"])

        if web_data["not_valid_before"]:
            doc.add_date("not_valid_before", datetime.fromisoformat(web_data["not_valid_before"]["_value"]))
        if web_data["not_valid_after"]:
            doc.add_date("not_valid_after", datetime.fromisoformat(web_data["not_valid_after"]["_value"]))

        pdf_data = cert.get("pdf_data")
        add_keyword_paths(doc, "keywords_report", pdf_data.get("report_keywords"))
        add_keyword_paths(doc, "keywords_profile", pdf_data.get("pp_keywords"))
        doc.add_text("body_report", content["report"])
        doc.add_text("body_profile", content["profile"])

        return doc


@actor("pp_reindex_collection", "pp_reindex_collection", "updates", timedelta(hours=4))
def reindex_collection(to_reindex):  # pragma: no cover
    indexer = PPIndexer()
    indexer.reindex(to_reindex)


@actor("pp_reindex_all", "pp_reindex_all", "updates", timedelta(hours=1))
def reindex_all():  # pragma: no cover
    ids = [doc["_id"] for doc in mongo.db.pp.find({}, {"_id": 1})]
    to_reindex = list(ids)
    tasks = []
    for i in range(0, len(to_reindex), 1000):
        j = i + 1000
        tasks.append(reindex_collection.message_with_options(args=(to_reindex[i:j],), pipe_ignore=True))
    pipeline(tasks).run()


class PPArchiver(Archiver, PPMixin):
    """
    PP Dataset
    ==========

    ├── reports
    │   ├── pdf
    │   └── txt
    ├── pps
    │   ├── pdf
    │   └── txt
    └── dataset.json
    """

    def archive(self, ids, path, paths):
        with TemporaryDirectory() as tmpdir:
            logger.info(f"Archiving {path}")
            tmpdir = Path(tmpdir)

            (tmpdir / "dataset.json").symlink_to(paths["output_path"])

            self.map_artifact_dir(ids, paths["profile"], tmpdir / "pps")
            self.map_artifact_dir(ids, paths["report"], tmpdir / "reports")

            logger.info("Running tar...")
            subprocess.run(["tar", "-hczvf", path, "."], cwd=tmpdir)
            logger.info(f"Finished archiving {path}")


@actor("pp_archive", "pp_archive", "updates", timedelta(hours=4))
def archive(ids, paths):  # pragma: no cover
    archiver = PPArchiver()
    archiver.archive(ids, Path(current_app.instance_path) / current_app.config["DATASET_PATH_PP_ARCHIVE"], paths)


@actor("pp_archive_all", "pp_archive_all", "updates", timedelta(hours=1))
def archive_all():  # pragma: no cover
    ids = [doc["_id"] for doc in mongo.db.pp.find({}, {"_id": 1})]
    updater = PPUpdater()
    paths = updater.make_dataset_paths()
    archive.send(ids, {name: str(path) for name, path in paths.items()})


class PPUpdater(Updater, PPMixin):  # pragma: no cover
    def dataset_state(self, dset):
        return dset.state.to_dict()

    def notify(self, run_id):
        # No notifications for PP changes
        pass

    def reindex(self, to_reindex):
        reindex_collection.send(list(to_reindex))

    def archive(self, ids, paths):
        archive.send(ids, paths)


@actor("pp_update", "pp_update", "updates", timedelta(hours=16))
def update_data():  # pragma: no cover
    updater = PPUpdater()
    updater.update()
