import os
from collections import Counter
from datetime import datetime
from operator import itemgetter
from shutil import rmtree

import sentry_sdk
from celery.utils.log import get_task_logger
from pkg_resources import get_distribution
from sec_certs.dataset.fips import FIPSDataset
from sec_certs.sample.fips_iut import IUTSnapshot
from sec_certs.sample.fips_mip import MIPSnapshot

from .. import celery, mongo
from ..common.objformats import ObjFormat
from ..common.tasks import make_dataset_paths, process_new_certs, process_removed_certs, process_updated_certs

logger = get_task_logger(__name__)


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


@celery.task(ignore_result=True)
def update_data():  # pragma: no cover
    tool_version = get_distribution("sec-certs").version
    start = datetime.now()
    paths = make_dataset_paths("fips")

    dset = FIPSDataset({}, paths["dset_path"], "dataset", "Description")

    if not dset.auxillary_datasets_dir.exists():
        dset.auxillary_datasets_dir.mkdir(parents=True)
    if paths["cve_path"].exists():
        os.symlink(paths["cve_path"], dset.cve_dataset_path)
    if paths["cpe_path"].exists():
        os.symlink(paths["cpe_path"], dset.cpe_dataset_path)

    try:
        with sentry_sdk.start_span(op="fips.all", description="Get full FIPS dataset"):
            with sentry_sdk.start_span(op="fips.get_certs", description="Get certs from web"):
                dset.get_certs_from_web(update_json=False)
            with sentry_sdk.start_span(op="fips.convert_pdfs", description="Convert pdfs"):
                dset.convert_all_pdfs(update_json=False)
            with sentry_sdk.start_span(op="fips.scan_pdfs", description="Scan pdfs"):
                dset.pdf_scan(update_json=False)
            with sentry_sdk.start_span(op="fips.tables", description="Extract tables"):
                dset.extract_certs_from_tables(high_precision=True, update_json=False)
            with sentry_sdk.start_span(op="fips.finalize_results", description="Finalize results"):
                dset.finalize_results(update_json=False)
            with sentry_sdk.start_span(op="fips.write_json", description="Write JSON"):
                dset.to_json(paths["output_path"])
            with sentry_sdk.start_span(op="fips.move", description="Move files"):
                for cert in dset:
                    if cert.state.sp_path:
                        pdf_path = cert.state.sp_path
                        if pdf_path.exists():
                            pdf_dst = paths["target_pdf"] / f"{cert.dgst}.pdf"
                            if not pdf_dst.exists() or pdf_dst.stat().st_size < pdf_path.stat().st_size:
                                pdf_path.replace(pdf_dst)
                        txt_path = pdf_path.with_suffix(".pdf.txt")
                        if txt_path.exists():
                            txt_dst = paths["target_txt"] / f"{cert.dgst}.txt"
                            if not txt_dst.exists() or txt_dst.stat().st_size < txt_path.stat().st_size:
                                txt_path.replace(txt_dst)

        old_ids = set(map(itemgetter("_id"), mongo.db.fips.find({}, projection={"_id": 1})))
        current_ids = set(dset.certs.keys())

        new_ids = current_ids.difference(old_ids)
        removed_ids = old_ids.difference(current_ids)
        updated_ids = current_ids.intersection(old_ids)

        cert_states = Counter(key for cert in dset for key in cert.state.to_dict() if cert.state.to_dict()[key])

        end = datetime.now()
        update_result = mongo.db.fips_log.insert_one(
            {
                "start_time": start,
                "end_time": end,
                "tool_version": tool_version,
                "length": len(dset),
                "ok": True,
                "stats": {
                    "new_certs": len(new_ids),
                    "removed_ids": len(removed_ids),
                    "updated_ids": len(updated_ids),
                    "cert_states": dict(cert_states),
                },
            }
        )
        logger.info(f"Finished run {update_result.inserted_id}.")

        # TODO: Take dataset and certificate state into account when processing into DB.

        with sentry_sdk.start_span(op="fips.db", description="Process certs into DB."):
            process_new_certs("fips", "fips_diff", dset, new_ids, update_result.inserted_id, start)
            process_updated_certs("fips", "fips_diff", dset, updated_ids, update_result.inserted_id, start)
            # TODO: cert to_json can have different ordering of arrays than the one in DB
            #       this generates and excessive amount of cert updates, that are not really updates
            #       just non-determinism in the ordering.
            process_removed_certs("fips", "fips_diff", dset, removed_ids, update_result.inserted_id, start)
    except Exception as e:
        end = datetime.now()
        mongo.db.fips_log.insert_one(
            {
                "start_time": start,
                "end_time": end,
                "tool_version": tool_version,
                "length": len(dset),
                "ok": False,
                "error": str(e),
            }
        )
        raise e
    finally:
        rmtree(paths["dset_path"], ignore_errors=True)
