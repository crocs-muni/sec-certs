import shutil
from datetime import datetime
from pathlib import Path
from typing import ClassVar, Literal

from bs4 import BeautifulSoup
from pydantic import AnyHttpUrl

from sec_certs import constants
from sec_certs.configuration import config
from sec_certs.dataset.auxiliary_dataset_handling import AuxiliaryDatasetHandler
from sec_certs.dataset.dataset import Dataset, logger
from sec_certs.sample.protection_profile import ProtectionProfile
from sec_certs.serialization.json import ComplexSerializableType, serialize
from sec_certs.utils import helpers
from sec_certs.utils import parallel_processing as cert_processing
from sec_certs.utils.profiling import staged


class ProtectionProfileDataset(Dataset[ProtectionProfile], ComplexSerializableType):
    FULL_ARCHIVE_URL: ClassVar[AnyHttpUrl] = config.pp_latest_full_archive
    SNAPSHOT_URL: ClassVar[AnyHttpUrl] = config.pp_latest_snapshot

    def __init__(
        self,
        certs: dict[str, ProtectionProfile] = {},
        root_dir: str | Path = constants.DUMMY_NONEXISTING_PATH,
        name: str | None = None,
        description: str = "",
        state: Dataset.DatasetInternalState | None = None,
        aux_handlers: dict[type[AuxiliaryDatasetHandler], AuxiliaryDatasetHandler] = {},
    ):
        self.certs = certs
        self.timestamp = datetime.now()
        self.sha256_digest = "not implemented"
        self.name = name if name else type(self).__name__ + " dataset"
        self.description = description if description else datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        self.state = state if state else self.DatasetInternalState()
        self.aux_handlers = aux_handlers
        self.root_dir = Path(root_dir)
        """
        Class for processing ProtectionProfile samples. Inherits from `ComplexSerializableType` and base abstract `Dataset` class.
        """

    @property
    def json_path(self) -> Path:
        return self.root_dir / "pp.json"

    @property
    def reports_dir(self) -> Path:
        """
        Path to protection profile reports.
        """
        return self.root_dir / "reports"

    @property
    def pps_dir(self) -> Path:
        """
        Path to actual protection profiles.
        """
        return self.root_dir / "pps"

    @property
    def reports_pdf_dir(self) -> Path:
        """
        Path to pdfs of protection profile reports.
        """
        return self.reports_dir / "pdf"

    @property
    def reports_txt_dir(self) -> Path:
        """
        Path to txts of protection profile reports.
        """
        return self.reports_dir / "txt"

    @property
    def pps_pdf_dir(self) -> Path:
        """
        Path to pdfs of protection profiles
        """
        return self.pps_dir / "pdf"

    @property
    def pps_txt_dir(self) -> Path:
        """
        Path to txts of protection profiles.
        """
        return self.pps_dir / "txt"

    def _compute_heuristics_body(self):
        logger.info("Protection profile dataset has no heuristics to compute, skipping.")

    @property
    def web_dir(self) -> Path:
        """
        Path to directory with html sources downloaded from commoncriteriaportal.org
        """
        return self.root_dir / "web"

    HTML_URL = {
        "pp_active.html": constants.CC_PORTAL_BASE_URL + "/pps/index.cfm",
        "pp_archived.html": constants.CC_PORTAL_BASE_URL + "/pps/index.cfm?archived=1",
        "pp_collaborative.html": constants.CC_PORTAL_BASE_URL + "/pps/collaborativePP.cfm?cpp=1",
    }

    @property
    def active_html_tuples(self) -> list[tuple[str, Path]]:
        return [(x, self.web_dir / y) for y, x in self.HTML_URL.items() if "active" in y]

    @property
    def archived_html_tuples(self) -> list[tuple[str, Path]]:
        return [(x, self.web_dir / y) for y, x in self.HTML_URL.items() if "archived" in y]

    @property
    def collaborative_html_tuples(self) -> list[tuple[str, Path]]:
        return [(x, self.web_dir / y) for y, x in self.HTML_URL.items() if "collaborative" in y]

    @serialize
    @staged(logger, "Downloading and processing CSV and HTML files of certificates.")
    def get_certs_from_web(
        self,
        to_download: bool = True,
        keep_metadata: bool = True,
        get_active: bool = True,
        get_archived: bool = True,
        get_collaborative: bool = True,
    ) -> None:
        """
        Fetches list of protection profiles together with metadata from commoncriteriaportal.org
        """
        if to_download:
            self._download_html_resources(get_active, get_archived, get_collaborative)

        logger.info("Adding HTML certificates to ProtectionProfile dataset.")
        self.certs = self._get_all_certs_from_html(get_active, get_archived, get_collaborative)
        logger.info(f"The resulting dataset has {len(self)} certificates.")

        if not keep_metadata:
            shutil.rmtree(self.web_dir)

        self._set_local_paths()
        self.state.meta_sources_parsed = True

    def _get_all_certs_from_html(
        self, get_active: bool = True, get_archived: bool = True, get_collaborative: bool = True
    ) -> dict[str, ProtectionProfile]:
        html_sources = []
        if get_active:
            html_sources.extend([x for x in self.HTML_URL if "active" in x])
        if get_archived:
            html_sources.extend([x for x in self.HTML_URL if "archived" in x])
        if get_collaborative:
            html_sources.extend([x for x in self.HTML_URL if "collaborative" in x])

        new_certs = {}
        for file in html_sources:
            partial_certs = self._parse_single_html(self.web_dir / file)
            logger.info(f"Parsed {len(partial_certs)} protection profiles from: {file}.")
            new_certs.update(partial_certs)
        return new_certs

    def _download_html_resources(
        self, get_active: bool = True, get_archived: bool = True, get_collaborative: bool = True
    ) -> None:
        self.web_dir.mkdir(parents=True, exist_ok=True)
        html_items = []
        if get_active:
            html_items.extend(self.active_html_tuples)
        if get_archived:
            html_items.extend(self.archived_html_tuples)
        if get_collaborative:
            html_items.extend(self.collaborative_html_tuples)

        html_urls, html_paths = [x[0] for x in html_items], [x[1] for x in html_items]

        logger.info("Downloading required csv and html files.")
        helpers.download_parallel(html_urls, html_paths)

    @staticmethod
    def _parse_single_html(file: Path) -> dict[str, ProtectionProfile]:
        def _parse_table(
            soup: BeautifulSoup,
            cert_status: Literal["active", "archived"],
            table_id: str,
            category_string: str,
            is_collaborative: bool,
        ) -> dict[str, ProtectionProfile]:
            tables = soup.find_all("table", id=table_id)
            if len(tables) > 1:
                raise ValueError(
                    f'The "{file.name}" was expected to contain 0-1 <table> element. Instead, it contains: {len(tables)} <table> elements.'
                )

            if not tables:
                return {}

            body = list(tables[0].find_all("tr"))[1:]
            table_certs = {}
            for row in body:
                try:
                    pp = ProtectionProfile.from_html_row(row, cert_status, category_string, is_collaborative)
                    table_certs[pp.dgst] = pp
                except ValueError as e:
                    logger.error(f"Error when creating ProtectionProfile object: {e}")

            return table_certs

        cert_status: Literal["active", "archived"] = "active" if "active" in file.name else "archived"
        is_collaborative = "collaborative" in file.name
        cc_table_ids = ["tbl" + x for x in constants.CC_CAT_ABBREVIATIONS]
        if is_collaborative:
            cc_table_ids = [x + "1" for x in cc_table_ids]
        cat_dict = dict(zip(cc_table_ids, constants.CC_CATEGORIES))

        with file.open("r") as handle:
            soup = BeautifulSoup(handle, "html5lib")

        certs = {}
        for key, val in cat_dict.items():
            certs.update(_parse_table(soup, cert_status, key, val, is_collaborative))

        return certs

    def _convert_all_pdfs_body(self, fresh=True):
        self._convert_reports_to_txt(fresh)
        self._convert_pps_to_txt(fresh)

    @staged(logger, "Converting PDFs of PP certification reports to text.")
    def _convert_reports_to_txt(self, fresh: bool = True):
        self.reports_txt_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.report.is_ok_to_convert(fresh)]

        if not fresh and certs_to_process:
            logger.info(
                f"Converting {len(certs_to_process)} PDFs of PP certification reports to text for which previous conversion failed."
            )

        cert_processing.process_parallel(
            ProtectionProfile.convert_report_pdf,
            certs_to_process,
            progress_bar_desc="Converting PDFs of PP certification reports to text.",
        )

    @staged(logger, "Converting PDFs of actual Protection Profiles to text.")
    def _convert_pps_to_txt(self, fresh: bool = True):
        self.pps_txt_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.pp.is_ok_to_convert(fresh)]

        if not fresh and certs_to_process:
            logger.info(
                f"Converting {len(certs_to_process)} PDFs of actual Protection Profiles to text for which previous conversion failed."
            )

        cert_processing.process_parallel(
            ProtectionProfile.convert_pp_pdf,
            certs_to_process,
            progress_bar_desc="Converting PDFs of actual Protection Profiles to text.",
        )

    def _download_all_artifacts_body(self, fresh=True):
        self._download_reports(fresh)
        self._download_pps(fresh)

    @staged(logger, "Downloading PDFs of PP certification reports.")
    def _download_reports(self, fresh: bool = True):
        self.reports_pdf_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.report.is_ok_to_download(fresh) and x.web_data.report_link]

        if not fresh and certs_to_process:
            logger.info(
                f"Downloading {len(certs_to_process)} PDFs of PP certification reports for which previous download failed."
            )

        cert_processing.process_parallel(
            ProtectionProfile.download_pdf_report,
            certs_to_process,
            progress_bar_desc="Downloading PDFs of PP certification reports.",
        )

    @staged(logger, "Downloading PDFs of actual Protection Profiles.")
    def _download_pps(self, fresh: bool = True):
        self.pps_pdf_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.pp.is_ok_to_download(fresh) and x.web_data.pp_link]

        if not fresh and certs_to_process:
            logger.info(
                f"Downloading {len(certs_to_process)} PDFs of actual Protection Profiles for which previous download failed."
            )

        cert_processing.process_parallel(
            ProtectionProfile.download_pdf_pp,
            certs_to_process,
            progress_bar_desc="Downloading PDFs of actual Protection Profiles.",
        )

    def extract_data(self):
        """
        Extracts pdf metadata and keywords from converted text documents.
        """
        logger.info("Extracting various data from certification artifacts.")
        self._extract_pdf_metadata()
        self._extract_pdf_keywords()

    @staged(logger, "Extracting metadata from certification artifacts.")
    def _extract_pdf_metadata(self):
        self._extract_report_metadata()
        self._extract_pp_metadata()

    @staged(logger, "Extracting keywords from certification artifacts.")
    def _extract_pdf_keywords(self):
        self._extract_report_keywords()
        self._extract_pp_keywords()

    def _extract_report_metadata(self):
        certs_to_process = [x for x in self if x.state.report.is_ok_to_analyze()]
        processed_certs = cert_processing.process_parallel(
            ProtectionProfile.extract_report_pdf_metadata,
            certs_to_process,
            use_threading=False,
            progress_bar_desc="Extracting metadata from PP certification reports.",
        )
        self.update_with_certs(processed_certs)

    def _extract_pp_metadata(self):
        certs_to_process = [x for x in self if x.state.pp.is_ok_to_analyze()]
        processed_certs = cert_processing.process_parallel(
            ProtectionProfile.extract_pp_pdf_metadata,
            certs_to_process,
            use_threading=False,
            progress_bar_desc="Extracting metadata from actual Protection Profiles.",
        )
        self.update_with_certs(processed_certs)

    def _extract_report_keywords(self):
        certs_to_process = [x for x in self if x.state.report.is_ok_to_analyze()]
        processed_certs = cert_processing.process_parallel(
            ProtectionProfile.extract_report_pdf_keywords,
            certs_to_process,
            use_threading=False,
            progress_bar_desc="Extracting keywords from PP certification reports.",
        )
        self.update_with_certs(processed_certs)

    def _extract_pp_keywords(self):
        certs_to_process = [x for x in self if x.state.pp.is_ok_to_analyze()]
        processed_certs = cert_processing.process_parallel(
            ProtectionProfile.extract_pp_pdf_keywords,
            certs_to_process,
            use_threading=False,
            progress_bar_desc="Extracting keywords from actual Protection Profiles.",
        )
        self.update_with_certs(processed_certs)

    def _set_local_paths(self):
        super()._set_local_paths()

        for cert in self:
            cert.set_local_paths(self.reports_pdf_dir, self.pps_pdf_dir, self.reports_txt_dir, self.pps_txt_dir)

    def process_auxiliary_datasets(self, **kwargs) -> None:
        """
        Dummy method to adhere to `Dataset` interface. `ProtectionProfile` dataset has currently no auxiliary datasets.
        This will just set the state `auxiliary_datasets_processed = True`
        """
        logger.info("Protection Profile dataset has no auxiliary datasets to process, skipping.")
        self.state.auxiliary_datasets_processed = True

    def get_pp_by_pp_link(self, pp_link: str) -> ProtectionProfile | None:
        """
        Given URL to PP pdf, will retrieve `ProtectionProfile` object in the dataset with the link, if such exists.
        """
        for pp in self:
            if pp.web_data.pp_link == pp_link:
                return pp
        return None
