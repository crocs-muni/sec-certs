from __future__ import annotations

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
