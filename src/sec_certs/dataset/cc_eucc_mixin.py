# mypy: ignore-errors
from __future__ import annotations

from abc import ABC
from pathlib import Path
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
from sec_certs.dataset.dataset import DatasetSubType, logger
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
from sec_certs.sample.cc_eucc_mixin import CC_EUCC_SampleMixin
from sec_certs.serialization.json import only_backed
from sec_certs.utils import parallel_processing as cert_processing
from sec_certs.utils.profiling import staged


class CertificateDatasetMixin(ABC):
    """
    Provides shared download and parsing functionality for
    EUCCDataset and CCDataset.
    """

    ALLOWED_DATASETS = {"EUCC", "CC"}
    dataset_name = ""

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if getattr(cls, "dataset_name", None) not in cls.ALLOWED_DATASETS:
            raise TypeError(f"{cls.__name__} must define dataset_name as one of {cls.ALLOWED_DATASETS}")

    @property
    @only_backed(throw=False)
    def reports_dir(self) -> Path:
        """
        Returns directory that holds files associated with certification reports
        """
        return self.certs_dir / "reports"

    @property
    @only_backed(throw=False)
    def reports_pdf_dir(self) -> Path:
        """
        Returns directory that holds PDFs associated with certification reports
        """
        return self.reports_dir / "pdf"

    @property
    @only_backed(throw=False)
    def reports_txt_dir(self) -> Path:
        """
        Returns directory that holds TXTs associated with certification reports
        """
        return self.reports_dir / "txt"

    @property
    @only_backed(throw=False)
    def reports_json_dir(self) -> Path:
        """
        Returns directory that holds JSONs associated with certification reports
        """
        return self.reports_dir / "json"

    @property
    @only_backed(throw=False)
    def targets_dir(self) -> Path:
        """
        Returns directory that holds files associated with security targets
        """
        return self.certs_dir / "targets"

    @property
    @only_backed(throw=False)
    def targets_pdf_dir(self) -> Path:
        """
        Returns directory that holds PDFs associated with security targets
        """
        return self.targets_dir / "pdf"

    @property
    @only_backed(throw=False)
    def targets_txt_dir(self) -> Path:
        """
        Returns directory that holds TXTs associated with security targets
        """
        return self.targets_dir / "txt"

    @property
    @only_backed(throw=False)
    def targets_json_dir(self) -> Path:
        """
        Returns directory that holds JSONs associated with certification targets
        """
        return self.targets_dir / "json"

    @property
    @only_backed(throw=False)
    def certificates_dir(self) -> Path:
        """
        Returns directory that holds files associated with the certificates
        """
        return self.certs_dir / "certificates"

    @property
    @only_backed(throw=False)
    def certificates_pdf_dir(self) -> Path:
        """
        Returns directory that holds PDFs associated with certificates
        """
        return self.certificates_dir / "pdf"

    @property
    @only_backed(throw=False)
    def certificates_txt_dir(self) -> Path:
        """
        Returns directory that holds TXTs associated with certificates
        """
        return self.certificates_dir / "txt"

    @property
    @only_backed(throw=False)
    def certificates_json_dir(self) -> Path:
        """
        Returns directory that holds JSONs associated with certification certificates
        """
        return self.certificates_dir / "json"

    def _extract_report_metadata(self):
        certs_to_process = [x for x in self if x.state.report.is_ok_to_analyze()]
        processed = cert_processing.process_parallel(
            CC_EUCC_SampleMixin.extract_report_pdf_metadata,
            certs_to_process,
            use_threading=False,
            progress_bar_desc="Extracting report metadata",
        )
        self.update_with_certs(processed)

    @staged(logger, "Extracting target metadata")
    def _extract_target_metadata(self):
        certs_to_process = [x for x in self if x.state.st.is_ok_to_analyze()]
        processed = cert_processing.process_parallel(
            CC_EUCC_SampleMixin.extract_st_pdf_metadata,
            certs_to_process,
            use_threading=False,
            progress_bar_desc="Extracting target metadata",
        )
        self.update_with_certs(processed)

    @staged(logger, "Extracting cert metadata")
    def _extract_cert_metadata(self):
        certs_to_process = [x for x in self if x.state.cert.is_ok_to_analyze()]
        processed = cert_processing.process_parallel(
            CC_EUCC_SampleMixin.extract_cert_pdf_metadata,
            certs_to_process,
            use_threading=False,
            progress_bar_desc="Extracting cert metadata",
        )
        self.update_with_certs(processed)

    @staged(logger, "Extracting report keywords")
    def _extract_report_keywords(self):
        certs_to_process = [x for x in self if x.state.report.is_ok_to_analyze()]
        processed = cert_processing.process_parallel(
            CC_EUCC_SampleMixin.extract_report_pdf_keywords,
            certs_to_process,
            use_threading=False,
            progress_bar_desc="Extracting report keywords",
        )
        self.update_with_certs(processed)

    @staged(logger, "Extracting target keywords")
    def _extract_target_keywords(self):
        certs_to_process = [x for x in self if x.state.st.is_ok_to_analyze()]
        processed = cert_processing.process_parallel(
            CC_EUCC_SampleMixin.extract_st_pdf_keywords,
            certs_to_process,
            use_threading=False,
            progress_bar_desc="Extracting target keywords",
        )
        self.update_with_certs(processed)

    @staged(logger, "Extracting cert keywords")
    def _extract_cert_keywords(self):
        certs_to_process = [x for x in self if x.state.cert.is_ok_to_analyze()]
        processed = cert_processing.process_parallel(
            CC_EUCC_SampleMixin.extract_cert_pdf_keywords,
            certs_to_process,
            use_threading=False,
            progress_bar_desc="Extracting cert keywords",
        )
        self.update_with_certs(processed)

    @staged(logger, "Extracting report frontpages")
    def _extract_report_frontpage(self) -> None:
        certs_to_process = [x for x in self if x.state.report.is_ok_to_analyze()]
        processed_certs = cert_processing.process_parallel(
            CC_EUCC_SampleMixin.extract_report_pdf_frontpage,
            certs_to_process,
            use_threading=False,
            progress_bar_desc="Extracting report frontpages",
        )
        self.update_with_certs(processed_certs)

    def _extract_all_metadata(self):
        self._extract_report_metadata()
        self._extract_target_metadata()
        self._extract_cert_metadata()

    def _extract_all_keywords(self):
        self._extract_report_keywords()
        self._extract_target_keywords()
        self._extract_cert_keywords()

    def _extract_all_frontpages(self):
        self._extract_report_frontpage()

    def extract_data(self) -> None:
        self._extract_all_metadata()
        self._extract_all_keywords()
        self._extract_all_frontpages()

    @staged(logger, f"Downloading PDFs of {dataset_name} certification reports.")
    def _download_reports(self, fresh: bool = True) -> None:
        self.reports_pdf_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.report.is_ok_to_download(fresh) and x.report_link]

        if not fresh and certs_to_process:
            logger.info(
                f"Downloading {len(certs_to_process)} PDFs of {self.dataset_name} certification reports for which previous download failed."
            )

        cert_processing.process_parallel(
            CC_EUCC_SampleMixin.download_pdf_report,
            certs_to_process,
            progress_bar_desc=f"Downloading PDFs of {self.dataset_name} certification reports",
        )

    @staged(logger, f"Downloading PDFs of {dataset_name} security targets.")
    def _download_targets(self, fresh: bool = True) -> None:
        self.targets_pdf_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.st.is_ok_to_download(fresh)]

        if not fresh and certs_to_process:
            logger.info(
                f"Downloading {len(certs_to_process)} PDFs of {self.dataset_name} security targets for which previous download failed.."
            )

        cert_processing.process_parallel(
            CC_EUCC_SampleMixin.download_pdf_st,
            certs_to_process,
            progress_bar_desc=f"Downloading PDFs of {self.dataset_name} security targets",
        )

    @staged(logger, f"Downloading PDFs of {dataset_name} certificates.")
    def _download_certs(self, fresh: bool = True) -> None:
        self.certificates_pdf_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.cert.is_ok_to_download(fresh)]

        if not fresh and certs_to_process:
            logger.info(
                f"Downloading {len(certs_to_process)} PDFs of {self.dataset_name} certificates for which previous download failed.."
            )

        cert_processing.process_parallel(
            CC_EUCC_SampleMixin.download_pdf_cert,
            certs_to_process,
            progress_bar_desc=f"Downloading PDFs of {self.dataset_name} certificates",
        )

    def _download_all_artifacts_body(self, fresh: bool = True) -> None:
        self._download_reports(fresh)
        self._download_targets(fresh)
        self._download_certs(fresh)

    def _convert_pdfs(
        self: DatasetSubType,
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

        convert_pdf_funcs = {
            "report": CC_EUCC_SampleMixin.convert_report_pdf,
            "st": CC_EUCC_SampleMixin.convert_st_pdf,
            "cert": CC_EUCC_SampleMixin.convert_cert_pdf,
        }

        convert_func = convert_pdf_funcs[short_name]
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
    def _convert_reports_pdfs(self: DatasetSubType, converter_cls: type[PDFConverter], fresh: bool = True) -> None:
        self._convert_pdfs("report", converter_cls, fresh)

    @staged(logger, "Converting PDFs of security targets.")
    def _convert_targets_pdfs(self: DatasetSubType, converter_cls: type[PDFConverter], fresh: bool = True) -> None:
        self._convert_pdfs("target", converter_cls, fresh)

    @staged(logger, "Converting PDFs of certificates.")
    def _convert_certs_pdfs(self: DatasetSubType, converter_cls: type[PDFConverter], fresh: bool = True) -> None:
        self._convert_pdfs("certificate", converter_cls, fresh)

    def _convert_all_pdfs_body(self, converter_cls: type[PDFConverter], fresh: bool = True) -> None:
        self._convert_reports_pdfs(converter_cls, fresh)
        self._convert_targets_pdfs(converter_cls, fresh)
        self._convert_certs_pdfs(converter_cls, fresh)

    def _compute_heuristics_body(self, skip_schemes: bool = False) -> None:
        link_to_protection_profiles(self.certs.values(), self.aux_handlers[ProtectionProfileDatasetHandler].dset)
        compute_cpe_heuristics(self.aux_handlers[CPEDatasetHandler].dset, self.certs.values())
        compute_related_cves(
            self.aux_handlers[CPEDatasetHandler].dset,
            self.aux_handlers[CVEDatasetHandler].dset,
            self.aux_handlers[CPEMatchDictHandler].dset,
            self.certs.values(),
        )
        compute_normalized_cert_ids(self.certs.values())
        compute_references(self.certs)
        compute_transitive_vulnerabilities(self.certs)

        if not skip_schemes:
            compute_scheme_data(self.aux_handlers[CCSchemeDatasetHandler].dset, self.certs)

        compute_cert_labs(self.certs.values())
        compute_eals(self.certs.values(), self.aux_handlers[ProtectionProfileDatasetHandler].dset)
        compute_sars(self.certs.values())
