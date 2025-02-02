import logging
import os
import subprocess
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

import sentry_sdk
from dramatiq import pipeline
from flask import current_app
from sec_certs.dataset import ProtectionProfileDataset
from sec_certs.utils.helpers import get_sha256_filepath

from .. import mongo, runtime_config
from ..cc import cc_categories
from ..common.diffs import DiffRenderer
from ..common.sentry import suppress_child_spans
from ..common.tasks import Indexer, Updater, actor

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


class CCRenderer(DiffRenderer, PPMixin):  # pragma: no cover
    def __init__(self):
        super().__init__()
        self.templates = {
            "new": "cc/notifications/diff_new.html.jinja2",
            "change": "cc/notifications/diff_change.html.jinja2",
            "remove": "cc/notifications/diff_remove.html.jinja2",
            "back": "cc/notifications/diff_back.html.jinja2",
        }
        self.k2map = {
            "web_data": ("CC portal data", False),
            "pdf_data": ("PDF extraction data", False),
            "state": ("state of the protection profile object", False),
            "heuristics": ("computed heuristics", True),
        }


class PPIndexer(Indexer, PPMixin):  # pragma: no cover
    def create_document(self, dgst, document, cert, content):
        category_id = cc_categories[cert["category"]]["id"]
        return {
            "dgst": dgst,
            "name": cert["name"],
            "document_type": document,
            "cert_id": None,
            "cert_schema": self.cert_schema,
            "category": category_id,
            "status": cert["web_data"]["status"],
            "scheme": cert["web_data"]["scheme"],
            "content": content,
        }


@actor("pp_reindex_collection", "pp_reindex_collection", "updates", timedelta(hours=4))
def reindex_collection(to_reindex):  # pragma: no cover
    indexer = PPIndexer()
    indexer.reindex(to_reindex)


@actor("pp_reindex_all", "pp_reindex_all", "updates", timedelta(hours=1))
def reindex_all():  # pragma: no cover
    ids = list(map(lambda doc: doc["_id"], mongo.db.pp.find({}, {"_id": 1})))
    to_reindex = [(dgst, doc) for dgst in ids for doc in ("report", "profile")]
    tasks = []
    for i in range(0, len(to_reindex), 1000):
        j = i + 1000
        tasks.append(reindex_collection.message_with_options(args=(to_reindex[i:j],), pipe_ignore=True))
    pipeline(tasks).run()


class PPArchiver(PPMixin):
    """
    PP Dataset
    ==========

    ├── reports
    │   ├── pdf
    │   └── txt
    ├── pps
    │   ├── pdf
    │   └── txt
    └── pp.json
    """

    def archive(self, path, paths):
        with TemporaryDirectory() as tmpdir:
            logger.info(f"Archiving {path}")
            tmpdir = Path(tmpdir)

            os.symlink(paths["output_path"], tmpdir / "pp.json")

            os.symlink(paths["pp"], tmpdir / "pps")
            os.symlink(paths["report"], tmpdir / "reports")

            logger.info("Running tar...")
            subprocess.run(["tar", "-hczvf", path, "."], cwd=tmpdir)
            logger.info(f"Finished archiving {path}")


@actor("pp_archive", "pp_archive", "updates", timedelta(hours=4))
def archive(paths):  # pragma: no cover
    archiver = PPArchiver()
    archiver.archive(Path(current_app.instance_path) / current_app.config["DATASET_PATH_PP_ARCHIVE"], paths)


class PPUpdater(Updater, PPMixin):  # pragma: no cover
    def process(self, dset, paths):
        to_reindex = set()
        with sentry_sdk.start_span(op="pp.all", description="Get full PP dataset"):
            if not self.skip_update or not paths["output_path"].exists():
                with sentry_sdk.start_span(op="pp.get_certs", description="Get certs from web"), suppress_child_spans():
                    dset.get_certs_from_web(update_json=False)
                with (
                    sentry_sdk.start_span(op="pp.auxiliary_datasets", description="Process auxiliary datasets"),
                    suppress_child_spans(),
                ):
                    dset.process_auxiliary_datasets(update_json=False)
                with (
                    sentry_sdk.start_span(op="pp.download_artifacts", description="Download artifacts"),
                    suppress_child_spans(),
                ):
                    dset.download_all_artifacts(update_json=False)
                with sentry_sdk.start_span(op="pp.convert_pdfs", description="Convert pdfs"), suppress_child_spans():
                    dset.convert_all_pdfs(update_json=False)
                with sentry_sdk.start_span(op="pp.analyze", description="Analyze certificates"), suppress_child_spans():
                    dset.analyze_certificates(update_json=False)
                with sentry_sdk.start_span(op="pp.write_json", description="Write JSON"), suppress_child_spans():
                    dset.to_json(paths["output_path"])

            with sentry_sdk.start_span(op="pp.move", description="Move files"), suppress_child_spans():
                for prof in dset:
                    if prof.state.pp.pdf_path and prof.state.pp.pdf_path.exists():
                        dst = paths["profile_pdf"] / f"{prof.dgst}.pdf"
                        if not dst.exists() or get_sha256_filepath(dst) != prof.state.pp.pdf_hash:
                            prof.state.pp.pdf_path.replace(dst)
                    if prof.state.pp.txt_path and prof.state.pp.txt_path.exists():
                        dst = paths["profile_txt"] / f"{prof.dgst}.txt"
                        if not dst.exists() or get_sha256_filepath(dst) != prof.state.pp.txt_hash:
                            prof.state.pp.txt_path.replace(dst)
                            to_reindex.add((prof.dgst, "profile"))
                    if prof.state.report.pdf_path and prof.state.report.pdf_path.exists():
                        dst = paths["report_pdf"] / f"{prof.dgst}.pdf"
                        if not dst.exists() or get_sha256_filepath(dst) != prof.state.report.pdf_hash:
                            prof.state.report.pdf_path.replace(dst)
                    if prof.state.report.txt_path and prof.state.report.txt_path.exists():
                        dst = paths["report_txt"] / f"{prof.dgst}.txt"
                        if not dst.exists() or get_sha256_filepath(dst) != prof.state.report.txt_hash:
                            prof.state.report.txt_path.replace(dst)
                            to_reindex.add((prof.dgst, "report"))
        return to_reindex

    def dataset_state(self, dset):
        return dset.state.to_dict()

    def notify(self, run_id):
        # No notifications for PP changes
        pass

    def reindex(self, to_reindex):
        reindex_collection.send(list(to_reindex))

    def archive(self, paths):
        archive.send(paths)


@actor("pp_update", "pp_update", "updates", timedelta(hours=16))
def update_data():  # pragma: no cover
    updater = PPUpdater()
    updater.update()
