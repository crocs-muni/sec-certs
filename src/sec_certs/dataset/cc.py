from __future__ import annotations

import itertools
import json
import locale
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import ClassVar, Iterator

import numpy as np
import pandas as pd
import requests
import tabula
from bs4 import BeautifulSoup, NavigableString, Tag

import sec_certs.utils.sanitization
from sec_certs import constants
from sec_certs.config.configuration import config
from sec_certs.dataset.cpe import CPEDataset
from sec_certs.dataset.cve import CVEDataset
from sec_certs.dataset.dataset import AuxillaryDatasets, Dataset, logger
from sec_certs.dataset.protection_profile import ProtectionProfileDataset
from sec_certs.model.reference_finder import ReferenceFinder
from sec_certs.model.sar_transformer import SARTransformer
from sec_certs.model.transitive_vulnerability_finder import TransitiveVulnerabilityFinder
from sec_certs.sample.cc import CCCertificate
from sec_certs.sample.cc_certificate_id import CertificateId
from sec_certs.sample.cc_maintenance_update import CCMaintenanceUpdate
from sec_certs.sample.protection_profile import ProtectionProfile
from sec_certs.serialization.json import ComplexSerializableType, CustomJSONDecoder, serialize
from sec_certs.utils import helpers as helpers
from sec_certs.utils import parallel_processing as cert_processing
from sec_certs.utils.sanitization import sanitize_navigable_string as sns


@dataclass
class CCAuxillaryDatasets(AuxillaryDatasets):
    cpe_dset: CPEDataset | None = None
    cve_dset: CVEDataset | None = None
    pp_dset: ProtectionProfileDataset | None = None
    mu_dset: CCDatasetMaintenanceUpdates | None = None


class CCDataset(Dataset[CCCertificate, CCAuxillaryDatasets], ComplexSerializableType):
    """
    Class that holds CCCertificate. Serializable into json, pandas, dictionary. Conveys basic certificate manipulations
    and dataset transformations. Many private methods that perform internal operations, feel free to exploit them.
    """

    def __init__(
        self,
        certs: dict[str, CCCertificate] = dict(),
        root_dir: str | Path = constants.DUMMY_NONEXISTING_PATH,
        name: str | None = None,
        description: str = "",
        state: Dataset.DatasetInternalState | None = None,
        auxillary_datasets: CCAuxillaryDatasets | None = None,
    ):
        self.certs = certs
        self.timestamp = datetime.now()
        self.sha256_digest = "not implemented"
        self.name = name if name else type(self).__name__ + " dataset"
        self.description = description if description else datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        self.state = state if state else self.DatasetInternalState()

        self.auxillary_datasets: CCAuxillaryDatasets = (
            auxillary_datasets if auxillary_datasets else CCAuxillaryDatasets()
        )

        self.root_dir = Path(root_dir)

    def to_pandas(self) -> pd.DataFrame:
        """
        Return self serialized into pandas DataFrame
        """
        df = pd.DataFrame([x.pandas_tuple for x in self.certs.values()], columns=CCCertificate.pandas_columns)
        df = df.set_index("dgst")

        df.not_valid_before = pd.to_datetime(df.not_valid_before, infer_datetime_format=True)
        df.not_valid_after = pd.to_datetime(df.not_valid_after, infer_datetime_format=True)
        df = df.astype(
            {"category": "category", "status": "category", "scheme": "category", "cert_lab": "category"}
        ).fillna(value=np.nan)
        df = df.loc[
            ~df.manufacturer.isnull()
        ]  # Manually delete one certificate with None manufacturer (seems to have many blank fields)

        # Categorize EAL
        df.eal = df.eal.fillna(value=np.nan)
        df.eal = pd.Categorical(df.eal, categories=sorted(df.eal.dropna().unique().tolist()), ordered=True)

        # Introduce year when cert got valid
        df["year_from"] = pd.DatetimeIndex(df.not_valid_before).year

        return df

    @property
    def reports_dir(self) -> Path:
        """
        Returns directory that holds files associated with certification reports
        """
        return self.certs_dir / "reports"

    @property
    def reports_pdf_dir(self) -> Path:
        """
        Returns directory that holds PDFs associated with certification reports
        """
        return self.reports_dir / "pdf"

    @property
    def reports_txt_dir(self) -> Path:
        """
        Returns directory that holds TXTs associated with certification reports
        """
        return self.reports_dir / "txt"

    @property
    def targets_dir(self) -> Path:
        """
        Returns directory that holds files associated with security targets
        """
        return self.certs_dir / "targets"

    @property
    def targets_pdf_dir(self) -> Path:
        """
        Returns directory that holds PDFs associated with security targets
        """
        return self.targets_dir / "pdf"

    @property
    def targets_txt_dir(self) -> Path:
        """
        Returns directory that holds TXTs associated with security targets
        """
        return self.targets_dir / "txt"

    @property
    def pp_dataset_path(self) -> Path:
        """
        Returns directory that holds files associated with Protection profiles
        """
        return self.auxillary_datasets_dir / "pp_dataset.json"

    @property
    def mu_dataset_dir(self) -> Path:
        """
        Returns directory that holds dataset of maintenance updates
        """
        return self.auxillary_datasets_dir / "maintenances"

    @property
    def mu_dataset_path(self) -> Path:
        """
        Returns json that holds the datase of maintenance updates
        """
        return self.mu_dataset_dir / "maintenance_updates.json"

    BASE_URL: ClassVar[str] = "https://www.commoncriteriaportal.org"

    HTML_PRODUCTS_URL = {
        "cc_products_active.html": BASE_URL + "/products/",
        "cc_products_archived.html": BASE_URL + "/products/index.cfm?archived=1",
    }
    HTML_LABS_URL = {"cc_labs.html": BASE_URL + "/labs"}
    CSV_PRODUCTS_URL = {
        "cc_products_active.csv": BASE_URL + "/products/certified_products.csv",
        "cc_products_archived.csv": BASE_URL + "/products/certified_products-archived.csv",
    }
    PP_URL = {
        "cc_pp_active.html": BASE_URL + "/pps/",
        "cc_pp_collaborative.html": BASE_URL + "/pps/collaborativePP.cfm?cpp=1",
        "cc_pp_archived.html": BASE_URL + "/pps/index.cfm?archived=1",
    }
    PP_CSV = {"cc_pp_active.csv": BASE_URL + "/pps/pps.csv", "cc_pp_archived.csv": BASE_URL + "/pps/pps-archived.csv"}

    @property
    def active_html_tuples(self) -> list[tuple[str, Path]]:
        """
        Returns List Tuple[str, Path] where first element is name of html file and second element is its Path.
        The files correspond to html files parsed from CC website that list all *active* certificates.
        """
        return [(x, self.web_dir / y) for y, x in self.HTML_PRODUCTS_URL.items() if "active" in y]

    @property
    def archived_html_tuples(self) -> list[tuple[str, Path]]:
        """
        Returns List Tuple[str, Path] where first element is name of html file and second element is its Path.
        The files correspond to html files parsed from CC website that list all *archived* certificates.
        """
        return [(x, self.web_dir / y) for y, x in self.HTML_PRODUCTS_URL.items() if "archived" in y]

    @property
    def active_csv_tuples(self) -> list[tuple[str, Path]]:
        """
        Returns List Tuple[str, Path] where first element is name of csv file and second element is its Path.
        The files correspond to csv files downloaded from CC website that list all *active* certificates.
        """
        return [(x, self.web_dir / y) for y, x in self.CSV_PRODUCTS_URL.items() if "active" in y]

    @property
    def archived_csv_tuples(self) -> list[tuple[str, Path]]:
        """
        Returns List Tuple[str, Path] where first element is name of csv file and second element is its Path.
        The files correspond to csv files downloaded from CC website that list all *archived* certificates.
        """
        return [(x, self.web_dir / y) for y, x in self.CSV_PRODUCTS_URL.items() if "archived" in y]

    @classmethod
    def from_web_latest(cls) -> CCDataset:
        """
        Fetches the fresh snapshot of CCDataset from seccerts.org
        """
        return cls.from_web(config.cc_latest_snapshot, "Downloading CC Dataset", "cc_latest_dataset.json")

    def _set_local_paths(self):
        super()._set_local_paths()

        if self.auxillary_datasets.pp_dset:
            self.auxillary_datasets.pp_dset.json_path = self.pp_dataset_path

        if self.auxillary_datasets.mu_dset:
            self.auxillary_datasets.mu_dset.root_dir = self.mu_dataset_dir

        for cert in self:
            cert.set_local_paths(self.reports_pdf_dir, self.targets_pdf_dir, self.reports_txt_dir, self.targets_txt_dir)
        # TODO: This forgets to set local paths for other auxillary datasets

    def _merge_certs(self, certs: dict[str, CCCertificate], cert_source: str | None = None) -> None:
        """
        Merges dictionary of certificates into the dataset. Assuming they all are CommonCriteria certificates
        """
        new_certs = {x.dgst: x for x in certs.values() if x not in self}
        certs_to_merge = [x for x in certs.values() if x in self]
        self.certs.update(new_certs)

        for crt in certs_to_merge:
            self[crt.dgst].merge(crt, cert_source)

        logger.info(f"Added {len(new_certs)} new and merged further {len(certs_to_merge)} certificates to the dataset.")

    def _download_csv_html_resources(self, get_active: bool = True, get_archived: bool = True) -> None:
        self.web_dir.mkdir(parents=True, exist_ok=True)

        html_items = []
        csv_items = []
        if get_active is True:
            html_items.extend(self.active_html_tuples)
            csv_items.extend(self.active_csv_tuples)
        if get_archived is True:
            html_items.extend(self.archived_html_tuples)
            csv_items.extend(self.archived_csv_tuples)

        html_urls, html_paths = [x[0] for x in html_items], [x[1] for x in html_items]
        csv_urls, csv_paths = [x[0] for x in csv_items], [x[1] for x in csv_items]

        logger.info("Downloading required csv and html files.")
        helpers.download_parallel(html_urls, html_paths)
        helpers.download_parallel(csv_urls, csv_paths)

    @serialize
    def get_certs_from_web(
        self, to_download: bool = True, keep_metadata: bool = True, get_active: bool = True, get_archived: bool = True
    ) -> None:
        """
        Downloads CSV and HTML files that hold lists of certificates from common criteria website. Parses these files
        and constructs CCCertificate objects, fills the dataset with those.

        :param bool to_download: If CSV and HTML files shall be downloaded (or existing files utilized), defaults to True
        :param bool keep_metadata: If CSV and HTML files shall be kept on disk after download, defaults to True
        :param bool get_active: If active certificates shall be parsed, defaults to True
        :param bool get_archived: If archived certificates shall be parsed, defaults to True
        """
        if to_download is True:
            self._download_csv_html_resources(get_active, get_archived)

        logger.info("Adding CSV certificates to CommonCriteria dataset.")
        csv_certs = self._get_all_certs_from_csv(get_active, get_archived)
        self._merge_certs(csv_certs, cert_source="csv")

        # Someway along the way, 3 certificates get lost.
        logger.info("Adding HTML certificates to CommonCriteria dataset.")
        html_certs = self._get_all_certs_from_html(get_active, get_archived)
        self._merge_certs(html_certs, cert_source="html")

        logger.info(f"The resulting dataset has {len(self)} certificates.")

        if not keep_metadata:
            shutil.rmtree(self.web_dir)

        self._set_local_paths()
        self.state.meta_sources_parsed = True

    def _get_all_certs_from_csv(self, get_active: bool, get_archived: bool) -> dict[str, CCCertificate]:
        """
        Creates dictionary of new certificates from csv sources.
        """
        csv_sources = list(self.CSV_PRODUCTS_URL.keys())
        csv_sources = [x for x in csv_sources if "active" not in x or get_active]
        csv_sources = [x for x in csv_sources if "archived" not in x or get_archived]

        new_certs = {}
        for file in csv_sources:
            partial_certs = self._parse_single_csv(self.web_dir / file)
            logger.info(f"Parsed {len(partial_certs)} certificates from: {file}")
            new_certs.update(partial_certs)
        return new_certs

    @staticmethod
    def _parse_single_csv(file: Path) -> dict[str, CCCertificate]:
        """
        Using pandas, this parses a single CSV file.
        """

        def map_ip_to_hostname(url: str) -> str:
            if not url:
                return url
            tokens = url.split("/")
            relative_path = "/" + "/".join(tokens[3:])
            return CCDataset.BASE_URL + relative_path

        def _get_primary_key_str(row: Tag):
            prim_key = row["category"] + row["cert_name"] + row["report_link"]
            return prim_key

        if "active" in str(file):
            cert_status = "active"
        else:
            cert_status = "archived"

        csv_header = [
            "category",
            "cert_name",
            "manufacturer",
            "scheme",
            "security_level",
            "protection_profiles",
            "not_valid_before",
            "not_valid_after",
            "report_link",
            "st_link",
            "maintenance_date",
            "maintenance_title",
            "maintenance_report_link",
            "maintenance_st_link",
        ]

        # TODO: Now skipping bad lines, smarter heuristics to be built for dumb files
        df = pd.read_csv(file, engine="python", encoding="windows-1252", on_bad_lines="skip")
        df = df.rename(columns={x: y for (x, y) in zip(list(df.columns), csv_header)})

        df["is_maintenance"] = ~df.maintenance_title.isnull()
        df = df.fillna(value="")

        df[["not_valid_before", "not_valid_after", "maintenance_date"]] = df[
            ["not_valid_before", "not_valid_after", "maintenance_date"]
        ].apply(pd.to_datetime)

        df["dgst"] = df.apply(lambda row: helpers.get_first_16_bytes_sha256(_get_primary_key_str(row)), axis=1)

        df_base = df.loc[~df.is_maintenance].copy()
        df_main = df.loc[df.is_maintenance].copy()

        df_base.report_link = df_base.report_link.map(map_ip_to_hostname)
        df_base.st_link = df_base.st_link.map(map_ip_to_hostname)

        df_main.maintenance_report_link = df_main.maintenance_report_link.map(map_ip_to_hostname)
        df_main.maintenance_st_link = df_main.maintenance_st_link.map(map_ip_to_hostname)

        n_all = len(df_base)
        n_deduplicated = len(df_base.drop_duplicates(subset=["dgst"]))
        if (n_dup := n_all - n_deduplicated) > 0:
            logger.warning(f"The CSV {file} contains {n_dup} duplicates by the primary key.")

        df_base = df_base.drop_duplicates(subset=["dgst"])
        df_main = df_main.drop_duplicates()

        profiles = {
            x.dgst: {
                ProtectionProfile(pp_name=y, pp_eal=None)
                for y in sec_certs.utils.sanitization.sanitize_protection_profiles(x.protection_profiles)
            }
            for x in df_base.itertuples()
        }
        updates: dict[str, set] = {x.dgst: set() for x in df_base.itertuples()}
        for x in df_main.itertuples():
            updates[x.dgst].add(
                CCCertificate.MaintenanceReport(
                    x.maintenance_date.date(), x.maintenance_title, x.maintenance_report_link, x.maintenance_st_link
                )
            )

        certs = {
            x.dgst: CCCertificate(
                cert_status,
                x.category,
                x.cert_name,
                x.manufacturer,
                x.scheme,
                x.security_level,
                x.not_valid_before,
                x.not_valid_after,
                x.report_link,
                x.st_link,
                None,
                None,
                profiles.get(x.dgst, None),
                updates.get(x.dgst, None),
                None,
                None,
                None,
            )
            for x in df_base.itertuples()
        }
        return certs

    def _get_all_certs_from_html(self, get_active: bool, get_archived: bool) -> dict[str, CCCertificate]:
        """
        Prepares dictionary of certificates from all html files.
        """
        html_sources = list(self.HTML_PRODUCTS_URL.keys())
        if get_active is False:
            html_sources = [x for x in html_sources if "active" not in x]
        if get_archived is False:
            html_sources = [x for x in html_sources if "archived" not in x]

        new_certs = {}
        for file in html_sources:
            partial_certs = self._parse_single_html(self.web_dir / file)
            logger.info(f"Parsed {len(partial_certs)} certificates from: {file}")
            new_certs.update(partial_certs)
        return new_certs

    @staticmethod
    def _parse_single_html(file: Path) -> dict[str, CCCertificate]:
        """
        Prepares a dictionary of certificates from a single html file.
        """

        def _get_timestamp_from_footer(footer):
            locale.setlocale(locale.LC_ALL, "en_US")
            footer_text = list(footer.stripped_strings)[0]
            date_string = footer_text.split(",")[1:3]
            time_string = footer_text.split(",")[3].split(" at ")[1]
            formatted_datetime = date_string[0] + date_string[1] + " " + time_string
            return datetime.strptime(formatted_datetime, " %B %d %Y %I:%M %p")

        def _parse_table(
            soup: BeautifulSoup, cert_status: str, table_id: str, category_string: str
        ) -> dict[str, CCCertificate]:
            tables = soup.find_all("table", id=table_id)

            if not len(tables) <= 1:
                raise ValueError(
                    f'The "{file.name}" was expected to contain <1 <table> element. Instead, it contains: {len(tables)} <table> elements.'
                )

            if not tables:
                return {}

            table = tables[0]
            rows = list(table.find_all("tr"))
            # header, footer = rows[0], rows[1]
            body = rows[2:]

            # It's possible to obtain timestamp of the moment when the list was generated. It's identical for each table and should thus only be obtained once. Not necessarily in each table
            # timestamp = _get_timestamp_from_footer(footer)

            # The following unused snippet extracts expected number of certs from the table
            # caption_str = str(table.findAll('caption'))
            # n_expected_certs = int(caption_str.split(category_string + ' – ')[1].split(' Certified Products')[0])

            try:
                table_certs = {
                    x.dgst: x for x in [CCCertificate.from_html_row(row, cert_status, category_string) for row in body]
                }
            except ValueError as e:
                raise ValueError(f"Bad html file: {file.name} ({str(e)})") from e

            return table_certs

        if "active" in str(file):
            cert_status = "active"
        else:
            cert_status = "archived"

        cc_cat_abbreviations = ["AC", "BP", "DP", "DB", "DD", "IC", "KM", "MD", "MF", "NS", "OS", "OD", "DG", "TC"]
        cc_table_ids = ["tbl" + x for x in cc_cat_abbreviations]
        cc_categories = [
            "Access Control Devices and Systems",
            "Boundary Protection Devices and Systems",
            "Data Protection",
            "Databases",
            "Detection Devices and Systems",
            "ICs, Smart Cards and Smart Card-Related Devices and Systems",
            "Key Management Systems",
            "Mobility",
            "Multi-Function Devices",
            "Network and Network-Related Devices and Systems",
            "Operating Systems",
            "Other Devices and Systems",
            "Products for Digital Signatures",
            "Trusted Computing",
        ]
        cat_dict = {x: y for (x, y) in zip(cc_table_ids, cc_categories)}

        with file.open("r") as handle:
            soup = BeautifulSoup(handle, "html5lib")

        certs = {}
        for key, val in cat_dict.items():
            certs.update(_parse_table(soup, cert_status, key, val))

        return certs

    def _download_all_artifacts_body(self, fresh: bool = True) -> None:
        self._download_reports(fresh)
        self._download_targets(fresh)

    def _download_reports(self, fresh: bool = True) -> None:
        self.reports_pdf_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.report_is_ok_to_download(fresh) and x.report_link]

        if fresh:
            logger.info("Downloading PDFs of CC certification reports.")
        if not fresh and certs_to_process:
            logger.info(
                f"Downloading {len(certs_to_process)} PDFs of CC certification reports for which previous download failed."
            )

        cert_processing.process_parallel(
            CCCertificate.download_pdf_report,
            certs_to_process,
            progress_bar_desc="Downloading PDFs of CC certification reports",
        )

    def _download_targets(self, fresh: bool = True) -> None:
        self.targets_pdf_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.report_is_ok_to_download(fresh)]

        if fresh:
            logger.info("Downloading PDFs of CC security targets.")
        if not fresh and certs_to_process:
            logger.info(
                f"Downloading {len(certs_to_process)} PDFs of CC security targets for which previous download failed.."
            )

        cert_processing.process_parallel(
            CCCertificate.download_pdf_st,
            certs_to_process,
            progress_bar_desc="Downloading PDFs of CC security targets",
        )

    def _convert_reports_to_txt(self, fresh: bool = True) -> None:
        self.reports_txt_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.report_is_ok_to_convert(fresh)]

        if fresh:
            logger.info("Converting PDFs of certification reports to txt.")
        if not fresh and certs_to_process:
            logger.info(
                f"Converting {len(certs_to_process)} PDFs of certification reports to txt for which previous conversion failed."
            )

        cert_processing.process_parallel(
            CCCertificate.convert_report_pdf,
            certs_to_process,
            progress_bar_desc="Converting PDFs of certification reports to txt",
        )

    def _convert_targets_to_txt(self, fresh: bool = True) -> None:
        self.targets_txt_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.st_is_ok_to_convert(fresh)]

        if fresh:
            logger.info("Converting PDFs of security targets to txt.")
        if not fresh and certs_to_process:
            logger.info(
                f"Converting {len(certs_to_process)} PDFs of security targets to txt for which previous conversion failed."
            )

        cert_processing.process_parallel(
            CCCertificate.convert_st_pdf,
            certs_to_process,
            progress_bar_desc="Converting PDFs of security targets to txt",
        )

    def _convert_all_pdfs_body(self, fresh: bool = True) -> None:
        self._convert_reports_to_txt(fresh)
        self._convert_targets_to_txt(fresh)

    def _extract_report_metadata(self) -> None:
        logger.info("Extracting report metadata")
        certs_to_process = [x for x in self if x.state.report_is_ok_to_analyze()]
        processed_certs = cert_processing.process_parallel(
            CCCertificate.extract_report_pdf_metadata,
            certs_to_process,
            use_threading=False,
            progress_bar_desc="Extracting report metadata",
        )
        self.update_with_certs(processed_certs)

    def _extract_targets_metadata(self) -> None:
        logger.info("Extracting target metadata")
        certs_to_process = [x for x in self if x.state.st_is_ok_to_analyze()]
        processed_certs = cert_processing.process_parallel(
            CCCertificate.extract_st_pdf_metadata,
            certs_to_process,
            use_threading=False,
            progress_bar_desc="Extracting target metadata",
        )
        self.update_with_certs(processed_certs)

    def _extract_pdf_metadata(self) -> None:
        self._extract_report_metadata()
        self._extract_targets_metadata()

    def _extract_report_frontpage(self) -> None:
        logger.info("Extracting report frontpages")
        certs_to_process = [x for x in self if x.state.report_is_ok_to_analyze()]
        processed_certs = cert_processing.process_parallel(
            CCCertificate.extract_report_pdf_frontpage,
            certs_to_process,
            use_threading=False,
            progress_bar_desc="Extracting report frontpages",
        )
        self.update_with_certs(processed_certs)

    def _extract_targets_frontpage(self) -> None:
        logger.info("Extracting target frontpages")
        certs_to_process = [x for x in self if x.state.st_is_ok_to_analyze()]
        processed_certs = cert_processing.process_parallel(
            CCCertificate.extract_st_pdf_frontpage,
            certs_to_process,
            use_threading=False,
            progress_bar_desc="Extracting target frontpages",
        )
        self.update_with_certs(processed_certs)

    def _extract_pdf_frontpage(self) -> None:
        self._extract_report_frontpage()
        self._extract_targets_frontpage()

    def _extract_report_keywords(self) -> None:
        logger.info("Extracting report keywords")
        certs_to_process = [x for x in self if x.state.report_is_ok_to_analyze()]
        processed_certs = cert_processing.process_parallel(
            CCCertificate.extract_report_pdf_keywords,
            certs_to_process,
            use_threading=False,
            progress_bar_desc="Extracting report keywords",
        )
        self.update_with_certs(processed_certs)

    def _extract_targets_keywords(self) -> None:
        logger.info("Extracting target keywords")
        certs_to_process = [x for x in self if x.state.st_is_ok_to_analyze()]
        processed_certs = cert_processing.process_parallel(
            CCCertificate.extract_st_pdf_keywords,
            certs_to_process,
            use_threading=False,
            progress_bar_desc="Extracting target keywords",
        )
        self.update_with_certs(processed_certs)

    def _extract_pdf_keywords(self) -> None:
        self._extract_report_keywords()
        self._extract_targets_keywords()

    def extract_data(self) -> None:
        logger.info("Extracting various data from certification artifacts")
        self._extract_pdf_metadata()
        self._extract_pdf_frontpage()
        self._extract_pdf_keywords()

    def _compute_cert_labs(self) -> None:
        logger.info("Computing heuristics: Deriving information about laboratories involved in certification.")
        certs_to_process = [x for x in self if x.state.report_is_ok_to_analyze()]
        for cert in certs_to_process:
            cert.compute_heuristics_cert_lab()

    def _compute_normalized_cert_ids(self) -> None:
        logger.info("Computing heuristics: Deriving information about certificate ids from artifacts.")
        for cert in self:
            cert.compute_heuristics_cert_id()

    def _compute_transitive_vulnerabilities(self):
        logger.info("omputing heuristics: computing transitive vulnerabilities in referenc(ed/ing) certificates.")
        transitive_cve_finder = TransitiveVulnerabilityFinder(lambda cert: cert.heuristics.cert_id)
        transitive_cve_finder.fit(self.certs, lambda cert: cert.heuristics.report_references)

        for dgst in self.certs:
            transitive_cve = transitive_cve_finder.predict_single_cert(dgst)

            self.certs[dgst].heuristics.direct_transitive_cves = transitive_cve.direct_transitive_cves
            self.certs[dgst].heuristics.indirect_transitive_cves = transitive_cve.indirect_transitive_cves

    def _compute_heuristics(self) -> None:
        self._compute_normalized_cert_ids()
        super()._compute_heuristics()
        self._compute_cert_labs()
        self._compute_sars()

    def _compute_sars(self) -> None:
        logger.info("Computing heuristics: Computing SARs")
        transformer = SARTransformer().fit(self.certs.values())
        for cert in self:
            cert.heuristics.extracted_sars = transformer.transform_single_cert(cert)

    def _compute_references(self) -> None:
        def ref_lookup(kw_attr):
            def func(cert):
                kws = getattr(cert.pdf_data, kw_attr)
                if not kws:
                    return set()
                res = set()
                for scheme, matches in kws["cc_cert_id"].items():
                    for match in matches.keys():
                        try:
                            canonical = CertificateId(scheme, match).canonical
                            res.add(canonical)
                        except Exception:
                            res.add(match)
                return res

            return func

        logger.info("omputing heuristics: references between certificates.")
        for ref_source in ("report", "st"):
            kw_source = f"{ref_source}_keywords"
            dep_attr = f"{ref_source}_references"

            finder = ReferenceFinder()
            finder.fit(self.certs, lambda cert: cert.heuristics.cert_id, ref_lookup(kw_source))  # type: ignore

            for dgst in self.certs:
                setattr(self.certs[dgst].heuristics, dep_attr, finder.predict_single_cert(dgst, keep_unknowns=False))

    def process_auxillary_datasets(self, download_fresh: bool = False) -> None:
        """
        Processes all auxillary datasets needed during computation. On top of base-class processing,
        CC handles protection profiles and maintenance updates.
        """
        super().process_auxillary_datasets(download_fresh)
        self.auxillary_datasets.pp_dset = self.process_protection_profiles(to_download=download_fresh)
        self.auxillary_datasets.mu_dset = self.process_maintenance_updates(to_download=download_fresh)

    @serialize
    def process_protection_profiles(
        self, to_download: bool = True, keep_metadata: bool = True
    ) -> ProtectionProfileDataset:
        """
        Downloads new snapshot of dataset with processed protection profiles (if it doesn't exist) and links PPs
        with certificates within self. Assigns PPs to all certificates

        :param bool to_download: If dataset should be downloaded or fetched from json, defaults to True
        :param bool keep_metadata: If json related to the PP dataset should be kept on drive, defaults to True
        :raises RuntimeError: When building of PPDataset fails
        """
        logger.info("Processing protection profiles.")

        self.auxillary_datasets_dir.mkdir(parents=True, exist_ok=True)

        if to_download or not self.pp_dataset_path.exists():
            pp_dataset = ProtectionProfileDataset.from_web(self.pp_dataset_path)
        else:
            pp_dataset = ProtectionProfileDataset.from_json(self.pp_dataset_path)

        for cert in self:
            if cert.protection_profiles is None:
                raise RuntimeError("Building of the dataset probably failed - this should not be happening.")
            cert.protection_profiles = {pp_dataset.pps.get((x.pp_name, x.pp_link), x) for x in cert.protection_profiles}

        if not keep_metadata:
            self.pp_dataset_path.unlink()

        return pp_dataset

    def process_maintenance_updates(self, to_download: bool = True) -> CCDatasetMaintenanceUpdates:
        """
        Downloads or loads from json a dataset of maintenance updates. Runs analysis on that dataset if it's not completed.
        :return CCDatasetMaintenanceUpdates: the resulting dataset of maintenance updates
        """

        logger.info("Processing maintenace updates")
        self.mu_dataset_dir.mkdir(parents=True, exist_ok=True)

        if to_download or not self.mu_dataset_path.exists():
            maintained_certs: list[CCCertificate] = [x for x in self if x.maintenance_updates]
            updates = list(
                itertools.chain.from_iterable(CCMaintenanceUpdate.get_updates_from_cc_cert(x) for x in maintained_certs)
            )
            update_dset = CCDatasetMaintenanceUpdates(
                {x.dgst: x for x in updates}, root_dir=self.mu_dataset_dir, name="maintenance_updates"
            )
        else:
            update_dset = CCDatasetMaintenanceUpdates.from_json(self.mu_dataset_path)

        if not update_dset.state.artifacts_downloaded:
            update_dset.download_all_artifacts()
        if not update_dset.state.pdfs_converted:
            update_dset.convert_all_pdfs()
        if not update_dset.state.certs_analyzed:
            update_dset.extract_data()

        return update_dset


class CCDatasetMaintenanceUpdates(CCDataset, ComplexSerializableType):
    """
    Dataset of maintenance updates related to certificates of CCDataset dataset.
    Should be used merely for actions related to Maintenance updates: download pdfs, convert pdfs, extract data from pdfs
    """

    # Quite difficult to achieve correct behaviour with MyPy here, opting for ignore
    def __init__(
        self,
        certs: dict[str, CCMaintenanceUpdate] = dict(),  # type: ignore
        root_dir: Path = constants.DUMMY_NONEXISTING_PATH,
        name: str = "dataset name",
        description: str = "dataset_description",
        state: CCDataset.DatasetInternalState | None = None,
    ):
        super().__init__(certs, root_dir, name, description, state)  # type: ignore
        self.state.meta_sources_parsed = True

    @property
    def certs_dir(self) -> Path:
        return self.root_dir

    def __iter__(self) -> Iterator[CCMaintenanceUpdate]:
        yield from self.certs.values()  # type: ignore

    def _compute_heuristics(self) -> None:
        raise NotImplementedError

    def compute_related_cves(self) -> None:
        raise NotImplementedError

    def process_auxillary_datasets(self, download_fresh: bool = False) -> None:
        raise NotImplementedError

    def analyze_certificates(self) -> None:
        raise NotImplementedError

    def get_certs_from_web(
        self, to_download: bool = True, keep_metadata: bool = True, get_active: bool = True, get_archived: bool = True
    ) -> None:
        raise NotImplementedError

    @classmethod
    def from_json(cls, input_path: str | Path) -> CCDatasetMaintenanceUpdates:
        input_path = Path(input_path)
        with input_path.open("r") as handle:
            dset = json.load(handle, cls=CustomJSONDecoder)
        dset._root_dir = Path(input_path).parent
        return dset

    def to_pandas(self) -> pd.DataFrame:
        df = pd.DataFrame([x.pandas_tuple for x in self.certs.values()], columns=CCMaintenanceUpdate.pandas_columns)
        df = df.set_index("dgst")
        df.index.name = "dgst"

        df.maintenance_date = pd.to_datetime(df.maintenance_date, infer_datetime_format=True)
        df = df.fillna(value=np.nan)

        return df

    @classmethod
    def from_web_latest(cls) -> CCDatasetMaintenanceUpdates:
        with tempfile.TemporaryDirectory() as tmp_dir:
            dset_path = Path(tmp_dir) / "cc_maintenances_latest_dataset.json"
            helpers.download_file(config.cc_maintenances_latest_snapshot, dset_path)
            return cls.from_json(dset_path)

    def get_n_maintenances_df(self) -> pd.DataFrame:
        """
        Returns a DataFrame with CCCertificate digest as an index, and number of registered maintenances as a value
        """
        main_df = self.to_pandas()
        main_df.maintenance_date = main_df.maintenance_date.dt.date
        n_maintenances = (
            main_df.groupby("related_cert_digest").name.count().rename("n_maintenances").fillna(0).astype("int32")
        )

        n_maintenances.index.name = "dgst"
        return n_maintenances

    def get_maintenance_dates_df(self) -> pd.DataFrame:
        """
        Returns a DataFrame with CCCertificate digest as an index, and all the maintenance dates as a value.
        """
        main_dates = self.to_pandas()
        main_dates.maintenance_date = main_dates.maintenance_date.map(lambda x: [x])
        main_dates.index.name = "dgst"
        return main_dates.groupby("related_cert_digest").maintenance_date.agg("sum").rename("maintenance_dates")


class CCSchemeDataset:
    @staticmethod
    def _download_page(url, session=None):
        if session:
            conn = session
        else:
            conn = requests
        resp = conn.get(url, headers={"User-Agent": "seccerts.org"})
        if resp.status_code != requests.codes.ok:
            raise ValueError(f"Unable to download: status={resp.status_code}")
        return BeautifulSoup(resp.content, "html5lib")

    @staticmethod
    def get_australia_in_evaluation():
        # TODO: Information could be expanded by following url.
        soup = CCSchemeDataset._download_page(constants.CC_AUSTRALIA_CERTIFIED_URL)
        header = soup.find("h2", text="Products in evaluation")
        table = header.find_next_sibling("table")
        results = []
        for tr in table.find_all("tr"):
            tds = tr.find_all("td")
            if not tds:
                continue
            cert = {
                "vendor": sns(tds[0].text),
                "product": sns(tds[1].text),
                "url": constants.CC_AUSTRALIA_BASE_URL + tds[1].find("a")["href"],
                "level": sns(tds[2].text),
            }
            results.append(cert)
        return results

    @staticmethod
    def get_canada_certified():
        soup = CCSchemeDataset._download_page(constants.CC_CANADA_CERTIFIED_URL)
        tbody = soup.find("table").find("tbody")
        results = []
        for tr in tbody.find_all("tr"):
            tds = tr.find_all("td")
            if not tds:
                continue
            cert = {
                "product": sns(tds[0].text),
                "vendor": sns(tds[1].text),
                "level": sns(tds[2].text),
                "certification_date": sns(tds[3].text),
            }
            results.append(cert)
        return results

    @staticmethod
    def get_canada_in_evaluation():
        soup = CCSchemeDataset._download_page(constants.CC_CANADA_INEVAL_URL)
        tbody = soup.find("table").find("tbody")
        results = []
        for tr in tbody.find_all("tr"):
            tds = tr.find_all("td")
            if not tds:
                continue
            cert = {
                "product": sns(tds[0].text),
                "vendor": sns(tds[1].text),
                "level": sns(tds[2].text),
                "cert_lab": sns(tds[3].text),
            }
            results.append(cert)
        return results

    @staticmethod
    def get_france_certified():
        # TODO: Information could be expanded by following product link.
        base_soup = CCSchemeDataset._download_page(constants.CC_ANSSI_CERTIFIED_URL)
        category_nav = base_soup.find("ul", class_="nav-categories")
        results = []
        for li in category_nav.find_all("li"):
            a = li.find("a")
            url = a["href"]
            category_name = sns(a.text)
            soup = CCSchemeDataset._download_page(constants.CC_ANSSI_BASE_URL + url)
            table = soup.find("table", class_="produits-liste cc")
            if not table:
                continue
            tbody = table.find("tbody")
            for tr in tbody.find_all("tr"):
                tds = tr.find_all("td")
                if not tds:
                    continue
                cert = {
                    "product": sns(tds[0].text),
                    "vendor": sns(tds[1].text),
                    "level": sns(tds[2].text),
                    "id": sns(tds[3].text),
                    "certification_date": sns(tds[4].text),
                    "category": category_name,
                    "url": constants.CC_ANSSI_BASE_URL + tds[0].find("a")["href"],
                }
                results.append(cert)
        return results

    @staticmethod
    def get_germany_certified():
        # TODO: Information could be expanded by following url.
        base_soup = CCSchemeDataset._download_page(constants.CC_BSI_CERTIFIED_URL)
        category_nav = base_soup.find("ul", class_="no-bullet row")
        results = []
        for li in category_nav.find_all("li"):
            a = li.find("a")
            url = a["href"]
            category_name = sns(a.text)
            soup = CCSchemeDataset._download_page(constants.CC_BSI_BASE_URL + url)
            content = soup.find("div", class_="content").find("div", class_="column")
            for table in content.find_all("table"):
                tbody = table.find("tbody")
                header = table.find_parent("div", class_="wrapperTable").find_previous_sibling("h2")
                for tr in tbody.find_all("tr"):
                    tds = tr.find_all("td")
                    if len(tds) != 4:
                        continue
                    cert = {
                        "cert_id": sns(tds[0].text),
                        "product": sns(tds[1].text),
                        "vendor": sns(tds[2].text),
                        "certification_date": sns(tds[3].text),
                        "category": category_name,
                        "url": constants.CC_BSI_BASE_URL + tds[0].find("a")["href"],
                    }
                    if header is not None:
                        cert["subcategory"] = sns(header.text)
                    results.append(cert)
        return results

    @staticmethod
    def get_india_certified():
        pages = {0}
        seen_pages = set()
        results = []
        while pages:
            page = pages.pop()
            seen_pages.add(page)
            url = constants.CC_INDIA_CERTIFIED_URL + f"?page={page}"
            soup = CCSchemeDataset._download_page(url)

            # Update pages
            pager = soup.find("ul", class_="pager")
            for li in pager.find_all("li"):
                try:
                    new_page = int(li.text)
                except Exception:
                    continue
                if new_page not in seen_pages:
                    pages.add(new_page)

            # Parse table
            tbody = soup.find("div", class_="content").find("table").find("tbody")
            for tr in tbody.find_all("tr"):
                tds = tr.find_all("td")
                if not tds:
                    continue
                report_a = tds[5].find("a")
                target_a = tds[6].find("a")
                cert_a = tds[7].find("a")
                cert = {
                    "serial_number": sns(tds[0].text),
                    "product": sns(tds[1].text),
                    "sponsor": sns(tds[2].text),
                    "developer": sns(tds[3].text),
                    "level": sns(tds[4].text),
                    "report_link": report_a["href"],
                    "report_name": sns(report_a.text),
                    "target_link": target_a["href"],
                    "target_name": sns(target_a.text),
                    "cert_link": cert_a["href"],
                    "cert_name": sns(cert_a.text),
                }
                results.append(cert)
        return results

    @staticmethod
    def get_india_archived():
        pages = {0}
        seen_pages = set()
        results = []
        while pages:
            page = pages.pop()
            seen_pages.add(page)
            url = constants.CC_INDIA_ARCHIVED_URL + f"?page={page}"
            soup = CCSchemeDataset._download_page(url)

            # Update pages
            pager = soup.find("ul", class_="pager")
            for li in pager.find_all("li"):
                try:
                    new_page = int(li.text)
                except Exception:
                    continue
                if new_page not in seen_pages:
                    pages.add(new_page)

            # Parse table
            tbody = soup.find("div", class_="content").find("table").find("tbody")
            for tr in tbody.find_all("tr"):
                tds = tr.find_all("td")
                if not tds:
                    continue
                report_a = tds[5].find("a")
                target_a = tds[6].find("a")
                cert_a = tds[7].find("a")
                cert = {
                    "serial_number": sns(tds[0].text),
                    "product": sns(tds[1].text),
                    "sponsor": sns(tds[2].text),
                    "developer": sns(tds[3].text),
                    "level": sns(tds[4].text),
                    "report_link": report_a["href"],
                    "report_name": sns(report_a.text),
                    "target_link": target_a["href"],
                    "target_name": sns(target_a.text),
                    "cert_link": cert_a["href"],
                    "cert_name": sns(cert_a.text),
                    "certification_date": sns(tds[8].text),
                }
                results.append(cert)
        return results

    @staticmethod
    def get_italy_certified():  # noqa: C901
        soup = CCSchemeDataset._download_page(constants.CC_ITALY_CERTIFIED_URL)
        div = soup.find("div", class_="certificati")
        results = []
        for cert_div in div.find_all("div", recursive=False):
            title = cert_div.find("h3").text
            data_div = cert_div.find("div", class_="collapse")
            cert = {"title": title}
            for data_p in data_div.find_all("p"):
                p_text = sns(data_p.text)
                if ":" not in p_text:
                    continue
                p_name, p_data = p_text.split(":")
                p_data = p_data
                p_link = data_p.find("a")
                if "Fornitore" in p_name:
                    cert["supplier"] = p_data
                elif "Livello di garanzia" in p_name:
                    cert["level"] = p_data
                elif "Data emissione certificato" in p_name:
                    cert["certification_date"] = p_data
                elif "Data revisione" in p_name:
                    cert["revision_date"] = p_data
                elif "Rapporto di Certificazione" in p_name and p_link:
                    cert["report_link_it"] = constants.CC_ITALY_BASE_URL + p_link["href"]
                elif "Certification Report" in p_name and p_link:
                    cert["report_link_en"] = constants.CC_ITALY_BASE_URL + p_link["href"]
                elif "Traguardo di Sicurezza" in p_name and p_link:
                    cert["target_link"] = constants.CC_ITALY_BASE_URL + p_link["href"]
                elif "Nota su" in p_name and p_link:
                    cert["vulnerability_note_link"] = constants.CC_ITALY_BASE_URL + p_link["href"]
                elif "Nota di chiarimento" in p_name and p_link:
                    cert["clarification_note_link"] = constants.CC_ITALY_BASE_URL + p_link["href"]
            results.append(cert)
        return results

    @staticmethod
    def get_italy_in_evaluation():
        soup = CCSchemeDataset._download_page(constants.CC_ITALY_INEVAL_URL)
        div = soup.find("div", class_="valutazioni")
        results = []
        for cert_div in div.find_all("div", recursive=False):
            title = cert_div.find("h3").text
            data_div = cert_div.find("div", class_="collapse")
            cert = {"title": title}
            for data_p in data_div.find_all("p"):
                p_text = sns(data_p.text)
                if ":" not in p_text:
                    continue
                p_name, p_data = p_text.split(":")
                p_data = p_data
                if "Committente" in p_name:
                    cert["client"] = p_data
                elif "Livello di garanzia" in p_name:
                    cert["level"] = p_data
                elif "Tipologia prodotto" in p_name:
                    cert["product_type"] = p_data
            results.append(cert)
        return results

    @staticmethod
    def get_japan_certified():
        # TODO: Information could be expanded by following toe link.
        soup = CCSchemeDataset._download_page(constants.CC_JAPAN_CERTIFIED_URL)
        table = soup.find("div", id="cert_list").find("table")
        results = []
        trs = list(table.find_all("tr"))
        for tr in trs:
            tds = tr.find_all("td")
            if not tds:
                continue
            if len(tds) == 6:
                cert = {
                    "cert_id": sns(tds[0].text),
                    "supplier": sns(tds[1].text),
                    "toe_overseas_name": sns(tds[2].text),
                    "certification_date": sns(tds[3].text),
                    "claim": sns(tds[4].text),
                }
                toe_a = tds[2].find("a")
                if toe_a and "href" in toe_a.attrs:
                    cert["toe_overseas_link"] = constants.CC_JAPAN_CERT_BASE_URL + "/" + toe_a["href"]
                results.append(cert)
            if len(tds) == 1:
                cert = results[-1]
                cert["toe_japan_name"] = sns(tds[0].text)
                toe_a = tds[0].find("a")
                if toe_a and "href" in toe_a.attrs:
                    cert["toe_japan_link"] = constants.CC_JAPAN_CERT_BASE_URL + "/" + toe_a["href"]
        return results

    @staticmethod
    def get_japan_archived():
        # TODO: Information could be expanded by following toe link.
        soup = CCSchemeDataset._download_page(constants.CC_JAPAN_ARCHIVED_URL)
        table = soup.find("table")
        results = []
        trs = list(table.find_all("tr"))
        for tr in trs:
            tds = tr.find_all("td")
            if not tds:
                continue
            if len(tds) == 6:
                cert = {
                    "cert_id": sns(tds[0].text),
                    "supplier": sns(tds[1].text),
                    "toe_overseas_name": sns(tds[2].text),
                    "certification_date": sns(tds[3].text),
                    "claim": sns(tds[4].text),
                }
                toe_a = tds[2].find("a")
                if toe_a and "href" in toe_a.attrs:
                    cert["toe_overseas_link"] = constants.CC_JAPAN_CERT_BASE_URL + "/" + toe_a["href"]
                results.append(cert)
            if len(tds) == 1:
                cert = results[-1]
                cert["toe_japan_name"] = sns(tds[0].text)
                toe_a = tds[0].find("a")
                if toe_a and "href" in toe_a.attrs:
                    cert["toe_japan_link"] = constants.CC_JAPAN_CERT_BASE_URL + "/" + toe_a["href"]
        return results

    @staticmethod
    def get_japan_in_evaluation():
        # TODO: Information could be expanded by following toe link.
        soup = CCSchemeDataset._download_page(constants.CC_JAPAN_INEVAL_URL)
        table = soup.find("table")
        results = []
        for tr in table.find_all("tr"):
            tds = tr.find_all("td")
            if not tds:
                continue
            toe_a = tds[1].find("a")
            cert = {
                "supplier": sns(tds[0].text),
                "toe_name": sns(toe_a.text),
                "toe_link": constants.CC_JAPAN_BASE_URL + "/" + toe_a["href"],
                "claim": sns(tds[2].text),
            }
            results.append(cert)
        return results

    @staticmethod
    def get_malaysia_certified():
        soup = CCSchemeDataset._download_page(constants.CC_MALAYSIA_CERTIFIED_URL)
        main_div = soup.find("div", attrs={"itemprop": "articleBody"})
        tables = main_div.find_all("table", recursive=False)
        results = []
        for table in tables:
            category_name = sns(table.find_previous_sibling("h3").text)
            for tr in table.find_all("tr")[1:]:
                tds = tr.find_all("td")
                if len(tds) != 6:
                    continue
                cert = {
                    "category": category_name,
                    "level": sns(tds[0].text),
                    "cert_id": sns(tds[1].text),
                    "certification_date": sns(tds[2].text),
                    "product": sns(tds[3].text),
                    "developer": sns(tds[4].text),
                }
                results.append(cert)
        return results

    @staticmethod
    def get_malaysia_in_evaluation():
        soup = CCSchemeDataset._download_page(constants.CC_MALAYSIA_INEVAL_URL)
        main_div = soup.find("div", attrs={"itemprop": "articleBody"})
        tables = main_div.find_all("table", recursive=False)
        results = []
        for table in tables:
            category_name = sns(table.find_previous_sibling("h3").text)
            for tr in table.find_all("tr")[1:]:
                tds = tr.find_all("td")
                if len(tds) != 5:
                    continue
                cert = {
                    "category": category_name,
                    "level": sns(tds[0].text),
                    "project_id": sns(tds[1].text),
                    "toe_name": sns(tds[2].text),
                    "developer": sns(tds[3].text),
                    "expected_completion": sns(tds[4].text),
                }
                results.append(cert)
        return results

    @staticmethod
    def get_netherlands_certified():
        soup = CCSchemeDataset._download_page(constants.CC_NETHERLANDS_CERTIFIED_URL)
        main_div = soup.select("body > main > div > div > div > div:nth-child(2) > div.col-lg-9 > div:nth-child(3)")[0]
        rows = main_div.find_all("div", class_="row", recursive=False)
        modals = main_div.find_all("div", class_="modal", recursive=False)
        results = []
        for row, modal in zip(rows, modals):
            row_entries = row.find_all("a")
            modal_trs = modal.find_all("tr")
            cert = {
                "manufacturer": sns(row_entries[0].text),
                "product": sns(row_entries[1].text),
                "scheme": sns(row_entries[2].text),
                "cert_id": sns(row_entries[3].text),
            }
            for tr in modal_trs:
                th_text = tr.find("th").text
                td = tr.find("td")
                if "Manufacturer website" in th_text:
                    cert["manufacturer_link"] = td.find("a")["href"]
                elif "Assurancelevel" in th_text:
                    cert["level"] = sns(td.text)
                elif "Certificate" in th_text:
                    cert["cert_link"] = constants.CC_NETHERLANDS_BASE_URL + td.find("a")["href"]
                elif "Certificationreport" in th_text:
                    cert["report_link"] = constants.CC_NETHERLANDS_BASE_URL + td.find("a")["href"]
                elif "Securitytarget" in th_text:
                    cert["target_link"] = constants.CC_NETHERLANDS_BASE_URL + td.find("a")["href"]
                elif "Maintenance report" in th_text:
                    cert["maintenance_link"] = constants.CC_NETHERLANDS_BASE_URL + td.find("a")["href"]
            results.append(cert)
        return results

    @staticmethod
    def get_netherlands_in_evaluation():
        soup = CCSchemeDataset._download_page(constants.CC_NETHERLANDS_INEVAL_URL)
        table = soup.find("table")
        results = []
        for tr in table.find_all("tr")[1:]:
            tds = tr.find_all("td")
            cert = {
                "developer": sns(tds[0].text),
                "product": sns(tds[1].text),
                "category": sns(tds[2].text),
                "level": sns(tds[3].text),
                "certification_id": sns(tds[4].text),
            }
            results.append(cert)
        return results

    @staticmethod
    def _get_norway(url):
        # TODO: Information could be expanded by following product link.
        soup = CCSchemeDataset._download_page(url)
        results = []
        for tr in soup.find_all("tr", class_="certified-product"):
            tds = tr.find_all("td")
            cert = {
                "product": sns(tds[0].text),
                "product_link": tds[0].find("a")["href"],
                "category": sns(tds[1].find("p", class_="value").text),
                "developer": sns(tds[2].find("p", class_="value").text),
                "certification_date": sns(tds[3].find("time").text),
            }
            results.append(cert)
        return results

    @staticmethod
    def get_norway_certified():
        return CCSchemeDataset._get_norway(constants.CC_NORWAY_CERTIFIED_URL)

    @staticmethod
    def get_norway_archived():
        return CCSchemeDataset._get_norway(constants.CC_NORWAY_ARCHIVED_URL)

    @staticmethod
    def _get_korea(product_class):
        # TODO: Information could be expanded by following product link.
        session = requests.session()
        session.get(constants.CC_KOREA_EN_URL)
        # Get base page
        url = constants.CC_KOREA_CERTIFIED_URL + f"?product_class={product_class}"
        soup = CCSchemeDataset._download_page(url, session=session)
        seen_pages = set()
        pages = {1}
        results = []
        while pages:
            page = pages.pop()
            csrf = soup.find("form", id="fm").find("input", attrs={"name": "csrf"})["value"]
            resp = session.post(url, data={"csrf": csrf, "selectPage": page, "product_class": product_class})
            soup = BeautifulSoup(resp.content, "html5lib")
            tbody = soup.find("table", class_="cpl").find("tbody")
            for tr in tbody.find_all("tr"):
                tds = tr.find_all("td")
                if len(tds) != 6:
                    continue
                link = tds[0].find("a")
                id = link["id"].split("-")[1]
                cert = {
                    "product": sns(tds[0].text),
                    "cert_id": sns(tds[1].text),
                    "product_link": constants.CC_KOREA_PRODUCT_URL.format(id),
                    "vendor": sns(tds[2].text),
                    "level": sns(tds[3].text),
                    "category": sns(tds[4].text),
                    "certification_date": sns(tds[5].text),
                }
                results.append(cert)
            seen_pages.add(page)
            page_links = soup.find("div", class_="paginate").find_all("a", class_="number_off")
            for page_link in page_links:
                try:
                    new_page = int(page_link.text)
                    if new_page not in seen_pages:
                        pages.add(new_page)
                except Exception:
                    pass
        return results

    @staticmethod
    def get_korea_certified():
        return CCSchemeDataset._get_korea(product_class=1)

    @staticmethod
    def get_korea_suspended():
        return CCSchemeDataset._get_korea(product_class=2)

    @staticmethod
    def get_korea_archived():
        return CCSchemeDataset._get_korea(product_class=4)

    @staticmethod
    def _get_singapore(url):
        soup = CCSchemeDataset._download_page(url)
        table = soup.find("table")
        skip = False
        results = []
        category_name = None
        for tr in table.find_all("tr"):
            if skip:
                skip = False
                continue
            tds = tr.find_all("td")
            if len(tds) == 1:
                category_name = sns(tds[0].text)
                skip = True
                continue

            cert = {
                "product": sns(tds[0].text.split()[0]),
                "vendor": sns(tds[1].text),
                "level": sns(tds[2].text),
                "certification_date": sns(tds[3].text),
                "expiration_date": sns(tds[4].text),
                "category": category_name,
            }
            for link in tds[0].find_all("a"):
                link_text = sns(link.text)
                if link_text == "Certificate":
                    cert["cert_link"] = constants.CC_SINGAPORE_BASE_URL + link["href"]
                elif link_text in ("Certificate Report", "Certification Report"):
                    cert["report_link"] = constants.CC_SINGAPORE_BASE_URL + link["href"]
                elif link_text == "Security Target":
                    cert["target_link"] = constants.CC_SINGAPORE_BASE_URL + link["href"]
            results.append(cert)
        return results

    @staticmethod
    def get_singapore_certified():
        return CCSchemeDataset._get_singapore(constants.CC_SINGAPORE_CERTIFIED_URL)

    @staticmethod
    def get_singapore_in_evaluation():
        soup = CCSchemeDataset._download_page(constants.CC_SINGAPORE_CERTIFIED_URL)
        header = soup.find(lambda x: x.name == "h3" and x.text == "In Evaluation")
        table = header.find_next("table")
        results = []
        for tr in table.find_all("tr")[1:]:
            tds = tr.find_all("td")
            cert = {
                "name": sns(tds[0].text),
                "vendor": sns(tds[1].text),
                "level": sns(tds[2].text),
            }
            results.append(cert)
        return results

    @staticmethod
    def get_singapore_archived():
        return CCSchemeDataset._get_singapore(constants.CC_SINGAPORE_ARCHIVED_URL)

    @staticmethod
    def get_spain_certified():
        soup = CCSchemeDataset._download_page(constants.CC_SPAIN_CERTIFIED_URL)
        tbody = soup.find("table", class_="djc_items_table").find("tbody")
        results = []
        for tr in tbody.find_all("tr", recursive=False):
            tds = tr.find_all("td")
            cert = {
                "product": sns(tds[0].text),
                "product_link": constants.CC_SPAIN_BASE_URL + tds[0].find("a")["href"],
                "category": sns(tds[1].text),
                "manufacturer": sns(tds[2].text),
                "certification_date": sns(tds[3].find("td", class_="djc_value").text),
            }
            results.append(cert)
        return results

    @staticmethod
    def _get_sweden(url):
        # TODO: Information could be expanded by following product link.
        soup = CCSchemeDataset._download_page(url)
        nav = soup.find("main").find("nav", class_="component-nav-box__list")
        results = []
        for link in nav.find_all("a"):
            cert = {"product": sns(link.text), "product_link": constants.CC_SWEDEN_BASE_URL + link["href"]}
            results.append(cert)
        return results

    @staticmethod
    def get_sweden_certified():
        return CCSchemeDataset._get_sweden(constants.CC_SWEDEN_CERTIFIED_URL)

    @staticmethod
    def get_sweden_in_evaluation():
        return CCSchemeDataset._get_sweden(constants.CC_SWEDEN_INEVAL_URL)

    @staticmethod
    def get_sweden_archived():
        return CCSchemeDataset._get_sweden(constants.CC_SWEDEN_ARCHIVED_URL)

    @staticmethod
    def get_turkey_certified():
        results = []
        with tempfile.TemporaryDirectory() as tmpdir:
            pdf_path = Path(tmpdir) / "turkey.pdf"
            resp = requests.get(constants.CC_TURKEY_ARCHIVED_URL)
            if resp.status_code != requests.codes.ok:
                raise ValueError(f"Unable to download: status={resp.status_code}")
            with pdf_path.open("wb") as f:
                f.write(resp.content)
            dfs = tabula.read_pdf(str(pdf_path), pages="all")
            for df in dfs:
                for line in df.values:
                    cert = {
                        # TODO: Split item number and generate several dicts for a range they include.
                        "item_no": line[0],
                        "developer": line[1],
                        "product": line[2],
                        "cc_version": line[3],
                        "level": line[4],
                        "cert_lab": line[5],
                        "certification_date": line[6],
                        "expiration_date": line[7],
                        # TODO: Parse "Ongoing Evaluation" out of this field as well.
                        "archived": isinstance(line[9], str) and "Archived" in line[9],
                    }
                    results.append(cert)
        return results

    @staticmethod
    def get_usa_certified():
        # TODO: Information could be expanded by following product link.
        # TODO: Information could be expanded by following the cc_claims (has links to protection profiles).
        soup = CCSchemeDataset._download_page(constants.CC_USA_CERTIFIED_URL)
        tbody = soup.find("table", class_="tablesorter").find("tbody")
        results = []
        for tr in tbody.find_all("tr"):
            tds = tr.find_all("td")
            vendor_span = tds[0].find("span", class_="b u")
            product_link = tds[0].find("a")
            scheme_img = tds[6].find("img")
            # Only return the US certifications.
            if scheme_img["title"] != "USA":
                continue
            cert = {
                "product": sns(product_link.text),
                "vendor": sns(vendor_span.text),
                "product_link": product_link["href"],
                "id": sns(tds[1].text),
                "cc_claim": sns(tds[2].text),
                "cert_lab": sns(tds[3].text),
                "certification_date": sns(tds[4].text),
                "assurance_maintenance_date": sns(tds[5].text),
            }
            results.append(cert)
        return results

    @staticmethod
    def get_usa_in_evaluation():
        # TODO: Information could be expanded by following the cc_claims (has links to protection profiles).
        soup = CCSchemeDataset._download_page(constants.CC_USA_INEVAL_URL)
        tbody = soup.find("table", class_="tablesorter").find("tbody")
        results = []
        for tr in tbody.find_all("tr"):
            tds = tr.find_all("td")
            vendor_span = tds[0].find("span", class_="b u")
            product_name = None
            for child in tds[0].children:
                if isinstance(child, NavigableString):
                    product_name = sns(child)
                    break
            cert = {
                "vendor": sns(vendor_span.text),
                "id": sns(tds[1].text),
                "cc_claim": sns(tds[2].text),
                "cert_lab": sns(tds[3].text),
                "kickoff_date": sns(tds[4].text),
            }
            if product_name:
                cert["product"] = product_name
            results.append(cert)
        return results

    @staticmethod
    def get_usa_archived():
        # TODO: Information could be expanded by following the cc_claims (has links to protection profiles).
        soup = CCSchemeDataset._download_page(constants.CC_USA_ARCHIVED_URL)
        tbody = soup.find("table", class_="tablesorter").find("tbody")
        results = []
        for tr in tbody.find_all("tr"):
            tds = tr.find_all("td")
            scheme_img = tds[5].find("img")
            # Only return the US certifications.
            if scheme_img["title"] != "USA":
                continue
            vendor_span = tds[0].find("span", class_="b u")
            product_name = None
            for child in tds[0].children:
                if isinstance(child, NavigableString):
                    product_name = sns(child)
                    break
            cert = {
                "vendor": sns(vendor_span.text),
                "id": sns(tds[1].text),
                "cc_claim": sns(tds[2].text),
                "cert_lab": sns(tds[3].text),
                "certification_date": sns(tds[4].text),
            }
            if product_name:
                cert["product"] = product_name
            results.append(cert)
        return results
