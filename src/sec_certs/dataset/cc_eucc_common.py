"""
This module contains logic shared exclusively between `CCDataset` and `EUCCDataset`.

It is intentionally scoped to these two datasets only, as they share a substantial
portion of processing and heuristics logic that does not apply to other dataset
types in the codebase.

Includes:
    - PDF downloading
    - PDF conversion
    - Metadata and keyword extraction
    - Heuristic computations
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from sec_certs.configuration import config
from sec_certs.converter import PDFConverter
from sec_certs.dataset.auxiliary_dataset_handling import (
    CCSchemeDatasetHandler,
    CPEDatasetHandler,
    CPEMatchDictHandler,
    CVEDatasetHandler,
    ProtectionProfileDatasetHandler,
)
from sec_certs.dataset.dataset import logger
from sec_certs.heuristics.common import (
    compute_cert_labs,
    compute_cpe_heuristics,
    compute_eals,
    compute_normalized_cert_ids,
    compute_references,
    compute_related_cves,
    compute_sars,
    compute_scheme_data,
    compute_transitive_vulnerabilities,
    link_to_protection_profiles,
)
from sec_certs.sample.cc_eucc_common import (
    convert_cert_pdf,
    convert_report_pdf,
    convert_st_pdf,
    download_pdf_cert,
    download_pdf_report,
    download_pdf_st,
    extract_cert_pdf_keywords,
    extract_cert_pdf_metadata,
    extract_report_pdf_frontpage,
    extract_report_pdf_keywords,
    extract_report_pdf_metadata,
    extract_st_pdf_keywords,
    extract_st_pdf_metadata,
)
from sec_certs.utils import parallel_processing as cert_processing
from sec_certs.utils.helpers import DocType
from sec_certs.utils.profiling import staged

if TYPE_CHECKING:
    from sec_certs.dataset.cc import CCDataset
    from sec_certs.dataset.eucc import EUCCDataset


def download_pdfs(
    obj: CCDataset | EUCCDataset,
    doc_type: DocType,
    fresh: bool = True,
) -> None:
    pdf_dir = getattr(obj, f"{doc_type.name.lower()}s_txt_dir")
    pdf_dir.mkdir(parents=True, exist_ok=True)

    certs_to_process = [
        x
        for x in obj
        if getattr(x.state, doc_type.short).is_ok_to_download(fresh) and (doc_type != DocType.REPORT or x.report_link)
    ]

    if not certs_to_process:
        return

    if not fresh:
        logger.info(
            f"Downloading {len(certs_to_process)} PDFs of {obj.dataset_name} {doc_type.long}s for which previous download failed."
        )

    download_pdf_funcs = {
        DocType.REPORT: download_pdf_report,
        DocType.TARGET: download_pdf_st,
        DocType.CERTIFICATE: download_pdf_cert,
    }

    cert_processing.process_parallel(
        download_pdf_funcs[doc_type],
        certs_to_process,
        progress_bar_desc=f"Downloading PDFs of {obj.dataset_name} {doc_type.long}s",
    )


@staged(logger, "Downloading PDFs of certification reports.")
def download_reports(obj: CCDataset | EUCCDataset, fresh: bool) -> None:
    download_pdfs(obj, DocType.REPORT, fresh)


@staged(logger, "Downloading PDFs of security targets.")
def download_targets(obj: CCDataset | EUCCDataset, fresh: bool) -> None:
    download_pdfs(obj, DocType.TARGET, fresh)


@staged(logger, "Downloading PDFs of certificates.")
def download_certs(obj: CCDataset | EUCCDataset, fresh: bool) -> None:
    download_pdfs(obj, DocType.CERTIFICATE, fresh)


def download_all_artifacts_body(obj: CCDataset | EUCCDataset, fresh: bool = True) -> None:
    download_reports(obj, fresh)
    download_targets(obj, fresh)
    download_certs(obj, fresh)


def convert_pdfs(
    obj: CCDataset | EUCCDataset,
    doc_type: DocType,
    converter_cls: type[PDFConverter],
    fresh: bool = True,
) -> None:
    txt_dir = getattr(obj, f"{doc_type.name.lower()}s_txt_dir")
    json_dir = getattr(obj, f"{doc_type.name.lower()}s_json_dir")
    txt_dir.mkdir(parents=True, exist_ok=True)
    json_dir.mkdir(parents=True, exist_ok=True)
    certs_to_process = [x for x in obj if getattr(x.state, doc_type.short).is_ok_to_convert(fresh)]

    if not certs_to_process:
        return

    if not fresh:
        logger.info(
            f"Converting {len(certs_to_process)} PDFs of {obj.dataset_name} {doc_type.long}s for which previous conversion failed."
        )

    convert_pdf_funcs = {
        DocType.REPORT: convert_report_pdf,
        DocType.TARGET: convert_st_pdf,
        DocType.CERTIFICATE: convert_cert_pdf,
    }

    processed_certs = cert_processing.process_parallel_with_instance(
        converter_cls,
        (),
        convert_pdf_funcs[doc_type],
        certs_to_process,
        config.pdf_conversion_workers,
        config.pdf_conversion_max_chunk_size,
        progress_bar_desc=f"Converting PDFs of {obj.dataset_name} {doc_type.long}s",
    )

    obj.update_with_certs(processed_certs)


@staged(logger, "Converting PDFs of certification reports.")
def convert_reports_pdfs(obj: CCDataset | EUCCDataset, converter_cls: type[PDFConverter], fresh: bool) -> None:
    convert_pdfs(obj, DocType.REPORT, converter_cls, fresh)


@staged(logger, "Converting PDFs of security targets.")
def convert_targets_pdfs(obj: CCDataset | EUCCDataset, converter_cls: type[PDFConverter], fresh: bool) -> None:
    convert_pdfs(obj, DocType.TARGET, converter_cls, fresh)


@staged(logger, "Converting PDFs of certificates.")
def convert_certs_pdfs(obj: CCDataset | EUCCDataset, converter_cls: type[PDFConverter], fresh: bool) -> None:
    convert_pdfs(obj, DocType.CERTIFICATE, converter_cls, fresh)


def convert_all_pdfs_body(obj: CCDataset | EUCCDataset, converter_cls: type[PDFConverter], fresh: bool):
    convert_reports_pdfs(obj, converter_cls, fresh)
    convert_targets_pdfs(obj, converter_cls, fresh)
    convert_certs_pdfs(obj, converter_cls, fresh)


def extract_generic(obj: CCDataset | EUCCDataset, doc_type: DocType, worker_func: Callable) -> None:
    certs_to_process = [x for x in obj if getattr(x.state, doc_type.short).is_ok_to_analyze()]

    if not certs_to_process:
        return

    processed = cert_processing.process_parallel(
        worker_func,
        certs_to_process,
        use_threading=False,
        progress_bar_desc=f"Extracting {obj.dataset_name} {doc_type.long} {worker_func.__name__.split('_')[-1]}",
    )
    obj.update_with_certs(processed)


@staged(logger, "Extracting report metadata")
def extract_report_metadata(obj: CCDataset | EUCCDataset):
    extract_generic(obj, DocType.REPORT, extract_report_pdf_metadata)


@staged(logger, "Extracting target metadata")
def extract_target_metadata(obj: CCDataset | EUCCDataset):
    extract_generic(obj, DocType.TARGET, extract_st_pdf_metadata)


@staged(logger, "Extracting cert metadata")
def extract_cert_metadata(obj: CCDataset | EUCCDataset):
    extract_generic(obj, DocType.CERTIFICATE, extract_cert_pdf_metadata)


@staged(logger, "Extracting report keywords")
def extract_report_keywords(obj: CCDataset | EUCCDataset):
    extract_generic(obj, DocType.REPORT, extract_report_pdf_keywords)


@staged(logger, "Extracting target keywords")
def extract_target_keywords(obj: CCDataset | EUCCDataset):
    extract_generic(obj, DocType.TARGET, extract_st_pdf_keywords)


@staged(logger, "Extracting cert keywords")
def extract_cert_keywords(obj: CCDataset | EUCCDataset):
    extract_generic(obj, DocType.CERTIFICATE, extract_cert_pdf_keywords)


# Frontpage (Special case)
@staged(logger, "Extracting report frontpages")
def extract_report_frontpage(obj: CCDataset | EUCCDataset) -> None:
    extract_generic(obj, DocType.REPORT, extract_report_pdf_frontpage)


def extract_all_metadata(obj: CCDataset | EUCCDataset):
    extract_report_metadata(obj)
    extract_target_metadata(obj)
    extract_cert_metadata(obj)


def extract_all_keywords(obj: CCDataset | EUCCDataset):
    extract_report_keywords(obj)
    extract_target_keywords(obj)
    extract_cert_keywords(obj)


def extract_all_frontpages(obj: CCDataset | EUCCDataset):
    extract_report_frontpage(obj)
    # We have no frontpage extraction for targets or certificates themselves, only for the reports.


def compute_heuristics_body(obj: CCDataset | EUCCDataset, skip_schemes: bool = False) -> None:
    link_to_protection_profiles(obj.certs.values(), obj.aux_handlers[ProtectionProfileDatasetHandler].dset)
    compute_cpe_heuristics(obj.aux_handlers[CPEDatasetHandler].dset, obj.certs.values())
    compute_related_cves(
        obj.aux_handlers[CPEDatasetHandler].dset,
        obj.aux_handlers[CVEDatasetHandler].dset,
        obj.aux_handlers[CPEMatchDictHandler].dset,
        obj.certs.values(),
    )

    compute_normalized_cert_ids(obj.certs.values())
    compute_references(obj.certs)
    compute_transitive_vulnerabilities(obj.certs)

    if not skip_schemes:
        compute_scheme_data(obj.aux_handlers[CCSchemeDatasetHandler].dset, obj.certs)

    compute_cert_labs(obj.certs.values())
    compute_eals(obj.certs.values(), obj.aux_handlers[ProtectionProfileDatasetHandler].dset)
    compute_sars(obj.certs.values())
