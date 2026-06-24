import logging
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

import sentry_sdk
from dramatiq import pipeline
from flask import current_app
from sec_certs.dataset.auxiliary_dataset_handling import CCSchemeDatasetHandler
from sec_certs.dataset.eucc import EUCCDataset
from sec_certs.utils.helpers import get_sha256_filepath
from tantivy import Document

from .. import mongo, runtime_config
from ..common.diffs import DiffRenderer
from ..common.sentry import suppress_child_spans
from ..common.tasks.archive import Archiver
from ..common.tasks.index import Indexer, add_keyword_paths
from ..common.tasks.notify import Notifier
from ..common.tasks.update import Updater
from ..common.tasks.utils import actor
from ..common.tasks.webui import KBUpdater
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
        doc.add_text("status", cert["status"])
        nvb = (cert.get("not_valid_before") or {}).get("_value")
        nva = (cert.get("not_valid_after") or {}).get("_value")
        if nvb:
            doc.add_date("not_valid_before", datetime.strptime(nvb, "%Y-%m-%d"))
        if nva:
            doc.add_date("not_valid_after", datetime.strptime(nva, "%Y-%m-%d"))
        doc.add_text("name", cert["name"] or "")
        doc.add_text("cert_id", cert.get("cert_id") or "")
        doc.add_text("cert_id_tokenized", cert.get("cert_id") or "")
        pdf_data = cert.get("pdf_data") or {}
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


class EUCCKBUpdater(KBUpdater, EUCCMixin):  # pragma: no cover
    pass


@actor("eucc_update_kb", "eucc_update_kb", "updates", timedelta(hours=12))
def update_kb(to_update):  # pragma: no cover
    updater = EUCCKBUpdater()
    updater.update(to_update)


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
    def process(
        self, dset: EUCCDataset, paths: dict[str, Path]
    ) -> tuple[set[tuple[str, str]], set[tuple[str, str, str | None]]]:
        to_reindex = set()
        to_update_kb: set[tuple[str, str, str | None]] = set()

        # reports_kb = get_knowledge_base(current_app.config["WEBUI_COLLECTION_CC_REPORTS"])
        # targets_kb = get_knowledge_base(current_app.config["WEBUI_COLLECTION_CC_TARGETS"])
        # reports_fmap = {}
        # for file in reports_kb["files"]:
        #    id = file["id"]
        #    name = file["meta"]["name"]
        #    updated = file["updated_at"]
        #    reports_fmap[name] = (id, updated)
        # targets_fmap = {}
        # for file in targets_kb["files"]:
        #    id = file["id"]
        #    name = file["meta"]["name"]
        #    updated = file["updated_at"]
        #     targets_fmap[name] = (id, updated)
        with sentry_sdk.start_span(op="eucc.all", description="Get full EUCC dataset"):
            if not self.skip_update or not paths["output_path"].exists():
                with (
                    sentry_sdk.start_span(op="eucc.get_certs", description="Get certs from web"),
                    suppress_child_spans(),
                ):
                    dset.get_certs_from_web()
                with (
                    sentry_sdk.start_span(
                        op="eucc.auxiliary_datasets",
                        description="Process auxiliary datasets (CVE, CPE, PP, MU, Scheme)",
                    ),
                    suppress_child_spans(),
                ):
                    dset.process_auxiliary_datasets(update_json=False, download_fresh=False)
                with (
                    sentry_sdk.start_span(op="eucc.download_artifacts", description="Download artifacts"),
                    suppress_child_spans(),
                ):
                    dset.download_all_artifacts()
                with sentry_sdk.start_span(op="eucc.convert_pdfs", description="Convert pdfs"), suppress_child_spans():
                    dset.convert_all_pdfs()
                with (
                    sentry_sdk.start_span(op="eucc.analyze", description="Analyze certificates"),
                    suppress_child_spans(),
                ):
                    dset.analyze_certificates()
                with sentry_sdk.start_span(op="eucc.write_json", description="Write JSON"), suppress_child_spans():
                    dset.to_json(paths["output_path"])
                    dset.aux_handlers[CCSchemeDatasetHandler].dset.to_json(paths["output_path_scheme"])

            with sentry_sdk.start_span(op="eucc.move", description="Move files"), suppress_child_spans():
                for cert in dset:
                    if cert.state.report.source_path and cert.state.report.source_path.exists():
                        dst = paths["report_pdf"] / f"{cert.dgst}.pdf"
                        if not dst.exists() or get_sha256_filepath(dst) != cert.state.report.source_hash:
                            cert.state.report.source_path.replace(dst)
                    if cert.state.report.txt_path and cert.state.report.txt_path.exists():
                        dst = paths["report_txt"] / f"{cert.dgst}.txt"
                        if not dst.exists() or get_sha256_filepath(dst) != cert.state.report.txt_hash:
                            cert.state.report.txt_path.replace(dst)
                            to_reindex.add(cert.dgst)
                        # name = f"{cert.dgst}.txt"
                        # if name not in reports_fmap:
                        #    to_update_kb.add((cert.dgst, "report", None))
                        # elif reports_fmap[name][1] < dst.stat().st_mtime:
                        #    to_update_kb.add((cert.dgst, "report", reports_fmap[name][0]))
                    if cert.state.st.source_path and cert.state.st.source_path.exists():
                        dst = paths["target_pdf"] / f"{cert.dgst}.pdf"
                        if not dst.exists() or get_sha256_filepath(dst) != cert.state.st.source_hash:
                            cert.state.st.source_path.replace(dst)
                    if cert.state.st.txt_path and cert.state.st.txt_path.exists():
                        dst = paths["target_txt"] / f"{cert.dgst}.txt"
                        if not dst.exists() or get_sha256_filepath(dst) != cert.state.st.txt_hash:
                            cert.state.st.txt_path.replace(dst)
                            to_reindex.add(cert.dgst)
                        # name = f"{cert.dgst}.txt"
                        # if name not in targets_fmap:
                        #    to_update_kb.add((cert.dgst, "target", None))
                        # elif targets_fmap[name][1] < dst.stat().st_mtime:
                        #    to_update_kb.add((cert.dgst, "target", targets_fmap[name][0]))
                    if cert.state.cert.source_path and cert.state.cert.source_path.exists():
                        dst = paths["cert_pdf"] / f"{cert.dgst}.pdf"
                        if not dst.exists() or get_sha256_filepath(dst) != cert.state.cert.source_hash:
                            cert.state.cert.source_path.replace(dst)
                    if cert.state.cert.txt_path and cert.state.cert.txt_path.exists():
                        dst = paths["cert_txt"] / f"{cert.dgst}.txt"
                        if not dst.exists() or get_sha256_filepath(dst) != cert.state.cert.txt_hash:
                            cert.state.cert.txt_path.replace(dst)
                            to_reindex.add(cert.dgst)
            with sentry_sdk.start_span(op="eucc.old_map", description="Update old digest map"), suppress_child_spans():
                for cert in dset:
                    if hasattr(cert, "old_dgst"):
                        mongo.db.eucc_old.replace_one(
                            {"_id": cert.old_dgst}, {"_id": cert.old_dgst, "hashid": cert.dgst}, upsert=True
                        )
                    if hasattr(cert, "older_dgst"):
                        mongo.db.eucc_old.replace_one(
                            {"_id": cert.older_dgst}, {"_id": cert.older_dgst, "hashid": cert.dgst}, upsert=True
                        )
        return to_reindex, to_update_kb

    def dataset_state(self, dset):
        return dset.state.to_dict()

    def notify(self, run_id):
        notify.send(str(run_id))

    def reindex(self, to_reindex):
        reindex_collection.send(list(to_reindex))

    def update_kb(self, to_update):
        update_kb.send(list(to_update))

    def archive(self, ids, paths):
        archive.send(ids, paths)


@actor("eucc_update", "eucc_update", "updates", timedelta(hours=16))
def update_data():  # pragma: no cover
    updater = EUCCUpdater()
    updater.update()
