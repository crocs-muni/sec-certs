from __future__ import annotations

from typing import Literal

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
from sec_certs.sample.common import (
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
from sec_certs.utils.profiling import staged


@staged(logger, "Extracting report metadata")
def extract_report_metadata(obj):
    certs_to_process = [x for x in obj if x.state.report.is_ok_to_analyze()]
    processed = cert_processing.process_parallel(
        extract_report_pdf_metadata,
        certs_to_process,
        use_threading=False,
        progress_bar_desc="Extracting report metadata",
    )
    obj.update_with_certs(processed)


@staged(logger, "Extracting target metadata")
def extract_target_metadata(obj):
    certs_to_process = [x for x in obj if x.state.st.is_ok_to_analyze()]
    processed = cert_processing.process_parallel(
        extract_st_pdf_metadata,
        certs_to_process,
        use_threading=False,
        progress_bar_desc="Extracting target metadata",
    )
    obj.update_with_certs(processed)


@staged(logger, "Extracting cert metadata")
def extract_cert_metadata(obj):
    certs_to_process = [x for x in obj if x.state.cert.is_ok_to_analyze()]
    processed = cert_processing.process_parallel(
        extract_cert_pdf_metadata,
        certs_to_process,
        use_threading=False,
        progress_bar_desc="Extracting cert metadata",
    )
    obj.update_with_certs(processed)


@staged(logger, "Extracting report keywords")
def extract_report_keywords(obj):
    certs_to_process = [x for x in obj if x.state.report.is_ok_to_analyze()]
    processed = cert_processing.process_parallel(
        extract_report_pdf_keywords,
        certs_to_process,
        use_threading=False,
        progress_bar_desc="Extracting report keywords",
    )
    obj.update_with_certs(processed)


@staged(logger, "Extracting target keywords")
def extract_target_keywords(obj):
    certs_to_process = [x for x in obj if x.state.st.is_ok_to_analyze()]
    processed = cert_processing.process_parallel(
        extract_st_pdf_keywords,
        certs_to_process,
        use_threading=False,
        progress_bar_desc="Extracting target keywords",
    )
    obj.update_with_certs(processed)


@staged(logger, "Extracting cert keywords")
def extract_cert_keywords(obj):
    certs_to_process = [x for x in obj if x.state.cert.is_ok_to_analyze()]
    processed = cert_processing.process_parallel(
        extract_cert_pdf_keywords,
        certs_to_process,
        use_threading=False,
        progress_bar_desc="Extracting cert keywords",
    )
    obj.update_with_certs(processed)


@staged(logger, "Extracting report frontpages")
def extract_report_frontpage(obj) -> None:
    certs_to_process = [x for x in obj if x.state.report.is_ok_to_analyze()]
    processed_certs = cert_processing.process_parallel(
        extract_report_pdf_frontpage,
        certs_to_process,
        use_threading=False,
        progress_bar_desc="Extracting report frontpages",
    )
    obj.update_with_certs(processed_certs)


def extract_all_metadata(obj):
    extract_report_metadata(obj)
    extract_target_metadata(obj)
    extract_cert_metadata(obj)


def extract_all_keywords(obj):
    extract_report_keywords(obj)
    extract_target_keywords(obj)
    extract_cert_keywords(obj)


def extract_all_frontpages(obj):
    extract_report_frontpage(obj)
    # We have no frontpage extraction for targets or certificates themselves, only for the reports.


def compute_heuristics_body(obj, skip_schemes: bool = False) -> None:
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

def _convert_pdfs(
self,
doc_type: Literal["report", "target", "certificate"],
converter_cls: type[PDFConverter],
fresh: bool = True,
) -> None:
    doc_type_map = {
        "report": {"short": "report", "long": "certification report"},
        "target": {"short": "st", "long": "security target"},
        "certificate": {"short": "cert", "long": "certificate"},
    }
    short_name = doc_type_map[doc_type]["short"]
    long_name = doc_type_map[doc_type]["long"]

    txt_dir = getattr(self, f"{doc_type}s_txt_dir")
    json_dir = getattr(self, f"{doc_type}s_json_dir")
    txt_dir.mkdir(parents=True, exist_ok=True)
    json_dir.mkdir(parents=True, exist_ok=True)
    certs_to_process = [x for x in self if getattr(x.state, short_name).is_ok_to_convert(fresh)]

    if not certs_to_process:
        return

    if not fresh:
        logger.info(
            f"Converting {len(certs_to_process)} PDFs of {long_name}s for which previous conversion failed."
        )

    convert_func = f"convert_{short_name}_pdf"
    processed_certs = cert_processing.process_parallel_with_instance(
        converter_cls,
        (),
        convert_func,
        certs_to_process,
        config.pdf_conversion_workers,
        config.pdf_conversion_max_chunk_size,
        progress_bar_desc=f"Converting PDFs of {long_name}s",
    )

    self.update_with_certs(processed_certs)

@staged(logger, "Converting PDFs of certification reports.")
def convert_reports_pdfs(self, converter_cls: type[PDFConverter], fresh: bool = True) -> None:
    self._convert_pdfs("report", converter_cls, fresh)

@staged(logger, "Converting PDFs of security targets.")
def convert_targets_pdfs(self, converter_cls: type[PDFConverter], fresh: bool = True) -> None:
    self._convert_pdfs("target", converter_cls, fresh)

@staged(logger, "Converting PDFs of certificates.")
def convert_certs_pdfs(self, converter_cls: type[PDFConverter], fresh: bool = True) -> None:
    self._convert_pdfs("certificate", converter_cls, fresh)

def convert_all_pdfs_body(obj, converter_cls: type[PDFConverter], fresh: bool = True) -> None:
    convert_reports_pdfs(converter_cls, fresh)
    convert_targets_pdfs(converter_cls, fresh)
    convert_certs_pdfs(converter_cls, fresh)

@staged(logger, "Downloading PDFs of CC certification reports.")
def download_reports(obj, fresh: bool = True) -> None:
    obj.reports_pdf_dir.mkdir(parents=True, exist_ok=True)
    certs_to_process = [x for x in obj if x.state.report.is_ok_to_download(fresh) and x.report_link]

    if not fresh and certs_to_process:
        logger.info(
            f"Downloading {len(certs_to_process)} PDFs of CC certification reports for which previous download failed."
        )

    cert_processing.process_parallel(
        download_pdf_report,
        certs_to_process,
        progress_bar_desc="Downloading PDFs of CC certification reports",
    )

@staged(logger, "Downloading PDFs of CC security targets.")
def download_targets(obj, fresh: bool = True) -> None:
    obj.targets_pdf_dir.mkdir(parents=True, exist_ok=True)
    certs_to_process = [x for x in obj if x.state.st.is_ok_to_download(fresh)]

    if not fresh and certs_to_process:
        logger.info(
            f"Downloading {len(certs_to_process)} PDFs of CC security targets for which previous download failed.."
        )

    cert_processing.process_parallel(
        download_pdf_st,
        certs_to_process,
        progress_bar_desc="Downloading PDFs of CC security targets",
    )

@staged(logger, "Downloading PDFs of CC certificates.")
def download_certs(obj, fresh: bool = True) -> None:
    obj.certificates_pdf_dir.mkdir(parents=True, exist_ok=True)
    certs_to_process = [x for x in obj if x.state.cert.is_ok_to_download(fresh)]

    if not fresh and certs_to_process:
        logger.info(
            f"Downloading {len(certs_to_process)} PDFs of CC certificates for which previous download failed.."
        )

    cert_processing.process_parallel(
        download_pdf_cert,
        certs_to_process,
        progress_bar_desc="Downloading PDFs of CC certificates",
    )

def download_all_artifacts_body(obj, fresh: bool = True) -> None:
    download_reports(obj, fresh)
    download_targets(obj, fresh)
    download_certs(obj, fresh)
