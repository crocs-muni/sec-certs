import copy
import itertools
import json
import locale
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, ClassVar, Dict, Iterator, List, Mapping, Optional, Set, Tuple, Union

import numpy as np
import pandas as pd
from bs4 import BeautifulSoup, Tag

from sec_certs import helpers as helpers
from sec_certs import parallel_processing as cert_processing
from sec_certs.config.configuration import config
from sec_certs.dataset.dataset import Dataset, logger
from sec_certs.dataset.protection_profile import ProtectionProfileDataset
from sec_certs.model.dependency_finder import DependencyFinder
from sec_certs.sample.cc_maintenance_update import CommonCriteriaMaintenanceUpdate
from sec_certs.sample.certificate import Certificate
from sec_certs.sample.common_criteria import CommonCriteriaCert
from sec_certs.sample.protection_profile import ProtectionProfile
from sec_certs.serialization.json import ComplexSerializableType, CustomJSONDecoder, serialize


class CCDataset(Dataset, ComplexSerializableType):
    @dataclass
    class DatasetInternalState(ComplexSerializableType):
        meta_sources_parsed: bool = False
        pdfs_downloaded: bool = False
        pdfs_converted: bool = False
        certs_analyzed: bool = False

        def __bool__(self):
            return any(vars(self))

    certs: Dict[str, "CommonCriteriaCert"]
    # TODO: Figure out how to type this. The problem is that this breaks covariance of the types, which mypy doesn't allow.

    def __init__(
        self,
        certs: Mapping[str, "Certificate"],
        root_dir: Path,
        name: str = "dataset name",
        description: str = "dataset_description",
        state: Optional[DatasetInternalState] = None,
    ):
        super().__init__(certs, root_dir, name, description)

        if state is None:
            state = self.DatasetInternalState()
        self.state = state

    def __iter__(self) -> Iterator[CommonCriteriaCert]:
        yield from self.certs.values()

    def to_dict(self):
        return {**{"state": self.state}, **super().to_dict()}

    def to_pandas(self):
        df = pd.DataFrame([x.pandas_tuple for x in self.certs.values()], columns=CommonCriteriaCert.pandas_columns)
        df = df.set_index("dgst")

        df.not_valid_before = pd.to_datetime(df.not_valid_before, infer_datetime_format=True)
        df.not_valid_after = pd.to_datetime(df.not_valid_after, infer_datetime_format=True)
        df = df.astype({"category": "category", "status": "category", "scheme": "category"})
        df = df.fillna(value=np.nan)

        return df

    @classmethod
    def from_dict(cls, dct: Dict):
        dset = super().from_dict(dct)
        dset.state = copy.deepcopy(dct["state"])
        return dset

    @Dataset.root_dir.setter  # type: ignore
    def root_dir(self, new_dir: Union[str, Path]):
        old_dset = copy.deepcopy(self)
        Dataset.root_dir.fset(self, new_dir)  # type: ignore
        self.set_local_paths()

        if self.state and old_dset.root_dir != Path(".."):
            logger.info(f"Changing root dir of partially processed dataset. All contents will get copied to {new_dir}")
            self.copy_dataset_contents(old_dset)
            self.to_json()

    def copy_dataset_contents(self, old_dset: "CCDataset"):
        if old_dset.state.meta_sources_parsed:
            try:
                shutil.copytree(old_dset.web_dir, self.web_dir)
            except FileNotFoundError as e:
                logger.warning(f"Attempted to copy non-existing file: {e}")
        if old_dset.state.pdfs_downloaded:
            try:
                shutil.copytree(old_dset.certs_dir, self.certs_dir)
            except FileNotFoundError as e:
                logger.warning(f"Attempted to copy non-existing file: {e}")
        if old_dset.state.certs_analyzed:
            try:
                shutil.copytree(old_dset.auxillary_datasets_dir, self.auxillary_datasets_dir)
            except FileNotFoundError as e:
                logger.warning(f"Attempted to copy non-existing file: {e}")

    @property
    def certs_dir(self) -> Path:
        return self.root_dir / "certs"

    @property
    def reports_dir(self) -> Path:
        return self.certs_dir / "reports"

    @property
    def reports_pdf_dir(self) -> Path:
        return self.reports_dir / "pdf"

    @property
    def reports_txt_dir(self) -> Path:
        return self.reports_dir / "txt"

    @property
    def targets_dir(self) -> Path:
        return self.certs_dir / "targets"

    @property
    def targets_pdf_dir(self) -> Path:
        return self.targets_dir / "pdf"

    @property
    def targets_txt_dir(self) -> Path:
        return self.targets_dir / "txt"

    @property
    def pp_dataset_path(self) -> Path:
        return self.auxillary_datasets_dir / "pp_dataset.json"

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
    def active_html_tuples(self) -> List[Tuple[str, Path]]:
        return [(x, self.web_dir / y) for y, x in self.HTML_PRODUCTS_URL.items() if "active" in y]

    @property
    def archived_html_tuples(self) -> List[Tuple[str, Path]]:
        return [(x, self.web_dir / y) for y, x in self.HTML_PRODUCTS_URL.items() if "archived" in y]

    @property
    def active_csv_tuples(self) -> List[Tuple[str, Path]]:
        return [(x, self.web_dir / y) for y, x in self.CSV_PRODUCTS_URL.items() if "active" in y]

    @property
    def archived_csv_tuples(self) -> List[Tuple[str, Path]]:
        return [(x, self.web_dir / y) for y, x in self.CSV_PRODUCTS_URL.items() if "archived" in y]

    @classmethod
    def from_web_latest(cls):
        with tempfile.TemporaryDirectory() as tmp_dir:
            dset_path = Path(tmp_dir) / "cc_latest_dataset.json"
            helpers.download_file(config.cc_latest_snapshot, dset_path)
            return cls.from_json(dset_path)

    def set_local_paths(self):
        for cert in self:
            cert.set_local_paths(self.reports_pdf_dir, self.targets_pdf_dir, self.reports_txt_dir, self.targets_txt_dir)

    def _merge_certs(self, certs: Dict[str, "CommonCriteriaCert"], cert_source: Optional[str] = None):
        """
        Merges dictionary of certificates into the dataset. Assuming they all are CommonCriteria certificates
        """
        new_certs = {x.dgst: x for x in certs.values() if x not in self}
        certs_to_merge = [x for x in certs.values() if x in self]
        self.certs.update(new_certs)

        for crt in certs_to_merge:
            self[crt.dgst].merge(crt, cert_source)

        logger.info(f"Added {len(new_certs)} new and merged further {len(certs_to_merge)} certificates to the dataset.")

    def download_csv_html_resources(self, get_active: bool = True, get_archived: bool = True):
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
        self._download_parallel(html_urls, html_paths)
        self._download_parallel(csv_urls, csv_paths)

    @serialize
    def process_protection_profiles(self, to_download: bool = True, keep_metadata: bool = True):
        logger.info("Processing protection profiles.")
        constructor: Dict[bool, Callable[..., ProtectionProfileDataset]] = {
            True: ProtectionProfileDataset.from_web,
            False: ProtectionProfileDataset.from_json,
        }
        if to_download is True and not self.auxillary_datasets_dir.exists():
            self.auxillary_datasets_dir.mkdir()
        pp_dataset = constructor[to_download](self.pp_dataset_path)

        for cert in self:
            if cert.protection_profiles is None:
                raise RuntimeError("Building of the dataset probably failed - this should not be happening.")
            cert.protection_profiles = {pp_dataset.pps.get((x.pp_name, x.pp_link), x) for x in cert.protection_profiles}

        if not keep_metadata:
            self.pp_dataset_path.unlink()

    @serialize
    def get_certs_from_web(
        self, to_download: bool = True, keep_metadata: bool = True, get_active: bool = True, get_archived: bool = True
    ):
        """
        Parses all metadata about certificates
        """
        if to_download is True:
            self.download_csv_html_resources(get_active, get_archived)

        logger.info("Adding CSV certificates to CommonCriteria dataset.")
        csv_certs = self._get_all_certs_from_csv(get_active, get_archived)
        self._merge_certs(csv_certs, cert_source="csv")

        # TODO: Someway along the way, 3 certificates get lost. Investigate and fix.
        logger.info("Adding HTML certificates to CommonCriteria dataset.")
        html_certs = self._get_all_certs_from_html(get_active, get_archived)
        self._merge_certs(html_certs, cert_source="html")

        logger.info(f"The resulting dataset has {len(self)} certificates.")

        if not keep_metadata:
            shutil.rmtree(self.web_dir)

        self.set_local_paths()
        self.state.meta_sources_parsed = True

    def _get_all_certs_from_csv(self, get_active: bool, get_archived: bool) -> Dict[str, "CommonCriteriaCert"]:
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
    def _parse_single_csv(file: Path) -> Dict[str, "CommonCriteriaCert"]:
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
        df = pd.read_csv(file, engine="python", encoding="windows-1252", error_bad_lines=False)
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
            x.dgst: set(
                [ProtectionProfile(pp_name=y) for y in helpers.sanitize_protection_profiles(x.protection_profiles)]
            )
            for x in df_base.itertuples()
        }
        updates: Dict[str, Set] = {x.dgst: set() for x in df_base.itertuples()}
        for x in df_main.itertuples():
            updates[x.dgst].add(
                CommonCriteriaCert.MaintenanceReport(
                    x.maintenance_date.date(), x.maintenance_title, x.maintenance_report_link, x.maintenance_st_link
                )
            )

        certs = {
            x.dgst: CommonCriteriaCert(
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

    def _get_all_certs_from_html(self, get_active: bool, get_archived: bool) -> Dict[str, "CommonCriteriaCert"]:
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
    def _parse_single_html(file: Path) -> Dict[str, "CommonCriteriaCert"]:
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
        ) -> Dict[str, "CommonCriteriaCert"]:
            tables = soup.find_all("table", id=table_id)
            assert len(tables) <= 1

            if not tables:
                return {}

            table = tables[0]
            rows = list(table.find_all("tr"))
            # header, footer = rows[0], rows[1]
            body = rows[2:]

            # TODO: It's possible to obtain timestamp of the moment when the list was generated. It's identical for each table and should thus only be obtained once. Not necessarily in each table
            # timestamp = _get_timestamp_from_footer(footer)

            # TODO: Do we have use for number of expected certs? We get rid of duplicites, so no use for assert expected == actual
            # caption_str = str(table.findAll('caption'))
            # n_expected_certs = int(caption_str.split(category_string + ' – ')[1].split(' Certified Products')[0])
            table_certs = {
                x.dgst: x for x in [CommonCriteriaCert.from_html_row(row, cert_status, category_string) for row in body]
            }

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

    def _download_reports(self, fresh=True):
        self.reports_pdf_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.report_is_ok_to_download(fresh) and x.report_link]
        cert_processing.process_parallel(
            CommonCriteriaCert.download_pdf_report,
            certs_to_process,
            config.n_threads,
            progress_bar_desc="Downloading reports",
        )

    def _download_targets(self, fresh=True):
        self.targets_pdf_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.report_is_ok_to_download(fresh)]
        cert_processing.process_parallel(
            CommonCriteriaCert.download_pdf_target,
            certs_to_process,
            config.n_threads,
            progress_bar_desc="Downloading targets",
        )

    @serialize
    def download_all_pdfs(self, fresh: bool = True):
        if self.state.meta_sources_parsed is False:
            logger.error("Attempting to download pdfs while not having csv/html meta-sources parsed. Returning.")
            return

        logger.info("Downloading CC sample reports")
        self._download_reports(fresh)

        logger.info("Downloading CC security targets")
        self._download_targets(fresh)

        if fresh is True:
            logger.info("Attempting to re-download failed report links.")
            self._download_reports(False)

            logger.info("Attempting to re-download failed security target links.")
            self._download_targets(False)

        self.state.pdfs_downloaded = True

    def _convert_reports_to_txt(self, fresh: bool = True):
        self.reports_txt_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.report_is_ok_to_convert(fresh)]
        cert_processing.process_parallel(
            CommonCriteriaCert.convert_report_pdf,
            certs_to_process,
            config.n_threads,
            progress_bar_desc="Converting reports to txt",
        )

    def _convert_targets_to_txt(self, fresh: bool = True):
        self.targets_txt_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.st_is_ok_to_convert(fresh)]
        cert_processing.process_parallel(
            CommonCriteriaCert.convert_target_pdf,
            certs_to_process,
            config.n_threads,
            progress_bar_desc="Converting targets to txt",
        )

    @serialize
    def convert_all_pdfs(self, fresh: bool = True):
        if self.state.pdfs_downloaded is False:
            logger.info("Attempting to convert pdf while not having them downloaded. Returning.")
            return

        logger.info("Converting CC sample reports to .txt")
        self._convert_reports_to_txt(fresh)

        logger.info("Converting CC security targets to .txt")
        self._convert_targets_to_txt(fresh)

        if fresh is True:
            logger.info("Attempting to re-convert failed report pdfs")
            self._convert_reports_to_txt(False)

            logger.info("Attempting to re-convert failed target pdfs")
            self._convert_targets_to_txt(False)

        self.state.pdfs_converted = True

    def update_with_certs(self, certs: List[CommonCriteriaCert]):
        if any([x not in self for x in certs]):
            logger.warning("Updating dataset with certificates outside of the dataset!")
        self.certs.update({x.dgst: x for x in certs})

    def _extract_report_metadata(self, fresh: bool = True):
        certs_to_process = [x for x in self if x.state.report_is_ok_to_analyze(fresh)]
        processed_certs = cert_processing.process_parallel(
            CommonCriteriaCert.extract_report_pdf_metadata,
            certs_to_process,
            config.n_threads,
            use_threading=False,
            progress_bar_desc="Extracting report metadata",
        )
        self.update_with_certs(processed_certs)

    def _extract_targets_metadata(self, fresh: bool = True):
        certs_to_process = [x for x in self if x.state.st_is_ok_to_analyze(fresh)]
        processed_certs = cert_processing.process_parallel(
            CommonCriteriaCert.extract_st_pdf_metadata,
            certs_to_process,
            config.n_threads,
            use_threading=False,
            progress_bar_desc="Extracting target metadata",
        )
        self.update_with_certs(processed_certs)

    def extract_pdf_metadata(self, fresh: bool = True):
        logger.info("Extracting pdf metadata from CC dataset")
        self._extract_report_metadata(fresh)
        self._extract_targets_metadata(fresh)

    def _extract_report_frontpage(self, fresh: bool = True):
        certs_to_process = [x for x in self if x.state.report_is_ok_to_analyze(fresh)]
        processed_certs = cert_processing.process_parallel(
            CommonCriteriaCert.extract_report_pdf_frontpage,
            certs_to_process,
            config.n_threads,
            use_threading=False,
            progress_bar_desc="Extracting report frontpages",
        )
        self.update_with_certs(processed_certs)

    def _extract_targets_frontpage(self, fresh: bool = True):
        certs_to_process = [x for x in self if x.state.st_is_ok_to_analyze(fresh)]
        processed_certs = cert_processing.process_parallel(
            CommonCriteriaCert.extract_st_pdf_frontpage,
            certs_to_process,
            config.n_threads,
            use_threading=False,
            progress_bar_desc="Extracting target frontpages",
        )
        self.update_with_certs(processed_certs)

    def extract_pdf_frontpage(self, fresh: bool = True):
        logger.info("Extracting pdf frontpages from CC dataset.")
        self._extract_report_frontpage(fresh)
        self._extract_targets_frontpage(fresh)

    def _extract_report_keywords(self, fresh: bool = True):
        certs_to_process = [x for x in self if x.state.report_is_ok_to_analyze(fresh)]
        processed_certs = cert_processing.process_parallel(
            CommonCriteriaCert.extract_report_pdf_keywords,
            certs_to_process,
            config.n_threads,
            use_threading=False,
            progress_bar_desc="Extracting report keywords",
        )
        self.update_with_certs(processed_certs)

    def _extract_targets_keywords(self, fresh: bool = True):
        certs_to_process = [x for x in self if x.state.st_is_ok_to_analyze(fresh)]
        processed_certs = cert_processing.process_parallel(
            CommonCriteriaCert.extract_st_pdf_keywords,
            certs_to_process,
            config.n_threads,
            use_threading=False,
            progress_bar_desc="Extracting target keywords",
        )
        self.update_with_certs(processed_certs)

    def extract_pdf_keywords(self, fresh: bool = True):
        logger.info("Extracting pdf keywords from CC dataset.")
        self._extract_report_keywords(fresh)
        self._extract_targets_keywords(fresh)

    def _extract_data(self, fresh: bool = True):
        logger.info("Extracting various stuff from converted txt filed from CC dataset.")
        self.extract_pdf_metadata(fresh)
        self.extract_pdf_frontpage(fresh)
        self.extract_pdf_keywords(fresh)

        if fresh is True:
            logger.info("Attempting to re-extract failed data from report txts")
            self._extract_report_metadata(False)
            self._extract_report_frontpage(False)
            self._extract_report_keywords(False)

            logger.info("Attempting to re-extract failed data from ST txts")
            self._extract_targets_metadata(False)
            self._extract_targets_frontpage(False)
            self._extract_targets_keywords(False)

    def _compute_cert_labs(self):
        logger.info("Deriving information about laboratories involved in certification.")
        certs_to_process = [x for x in self if x.state.report_is_ok_to_analyze()]
        for cert in certs_to_process:
            cert.compute_heuristics_cert_lab()

    def _compute_cert_ids(self):
        logger.info("Deriving information about sample ids from pdf scan.")
        certs_to_process = [x for x in self if x.state.report_is_ok_to_analyze()]
        for cert in certs_to_process:
            cert.compute_heuristics_cert_id()

    def _compute_heuristics(self, use_nist_cpe_matching_dict: bool = True):
        self._compute_cert_labs()
        self._compute_cert_ids()
        self._compute_dependencies()
        self.compute_cpe_heuristics()
        self.compute_related_cves(use_nist_cpe_matching_dict=use_nist_cpe_matching_dict)

    def _compute_dependencies(self):
        finder = DependencyFinder()
        finder.fit(self.certs)

        for dgst in self.certs:
            self.certs[dgst].heuristics.directly_affecting = finder.get_directly_affecting(dgst)
            self.certs[dgst].heuristics.indirectly_affecting = finder.get_indirectly_affecting(dgst)
            self.certs[dgst].heuristics.directly_affected_by = finder.get_directly_affected_by(dgst)
            self.certs[dgst].heuristics.indirectly_affected_by = finder.get_indirectly_affected_by(dgst)

    @serialize
    def analyze_certificates(self, fresh: bool = True):
        if self.state.pdfs_converted is False:
            logger.info(
                "Attempting run analysis of txt files while not having the pdf->txt conversion done. Returning."
            )
            return

        self._extract_data(fresh)
        self._compute_heuristics()

        self.state.certs_analyzed = True

    def get_certs_from_name(self, cert_name: str) -> List[Certificate]:
        return [crt for crt in self if crt.name == cert_name]

    def process_maintenance_updates(self):
        maintained_certs: List[CommonCriteriaCert] = [x for x in self if x.maintenance_updates]
        updates = list(
            itertools.chain.from_iterable(
                [CommonCriteriaMaintenanceUpdate.get_updates_from_cc_cert(x) for x in maintained_certs]
            )
        )
        update_dset: CCDatasetMaintenanceUpdates = CCDatasetMaintenanceUpdates(
            {x.dgst: x for x in updates}, root_dir=self.certs_dir / "maintenance", name="Maintenance updates"
        )
        update_dset.set_local_paths()
        update_dset.download_all_pdfs()
        update_dset.convert_all_pdfs()
        update_dset._extract_data()

    def generate_cert_name_keywords(self) -> Set[str]:
        df = self.to_pandas()
        certificate_names = set(df["name"])
        keywords = set(itertools.chain.from_iterable([x.lower().split(" ") for x in certificate_names]))
        keywords.add("1.02.013")
        return {x for x in keywords if len(x) > config.minimal_token_length}


class CCDatasetMaintenanceUpdates(CCDataset, ComplexSerializableType):
    """
    Should be used merely for actions related to Maintenance updates: download pdfs, convert pdfs, extract data from pdfs
    """

    # TODO: Types - if I use dictionary in CCDataset, I can't use more specific dictionary here (otherwise the CCDataset
    # one would have to be a Mapping - not mutable)
    certs: Dict[str, "CommonCriteriaMaintenanceUpdate"]  # type: ignore

    def __init__(
        self,
        certs: Mapping[str, "Certificate"],
        root_dir: Path,
        name: str = "dataset name",
        description: str = "dataset_description",
        state: Optional[CCDataset.DatasetInternalState] = None,
    ):
        super().__init__(certs, root_dir, name, description, state)
        self.state.meta_sources_parsed = True

    @property
    def certs_dir(self) -> Path:
        return self.root_dir

    def __iter__(self) -> Iterator[CommonCriteriaMaintenanceUpdate]:
        yield from self.certs.values()

    def _compute_heuristics(self, download_fresh_cpes: bool = False):
        raise NotImplementedError

    def compute_related_cves(self, download_fresh_cves: bool = False):
        raise NotImplementedError

    @classmethod
    def from_json(cls, input_path: Union[str, Path]):
        input_path = Path(input_path)
        with input_path.open("r") as handle:
            dset = json.load(handle, cls=CustomJSONDecoder)
        return dset

    def to_pandas(self):
        df = pd.DataFrame(
            [x.pandas_tuple for x in self.certs.values()], columns=CommonCriteriaMaintenanceUpdate.pandas_columns
        )
        df = df.set_index("dgst")
        df.index.name = "dgst"

        df.maintenance_date = pd.to_datetime(df.maintenance_date, infer_datetime_format=True)
        df = df.fillna(value=np.nan)

        return df

    @classmethod
    def from_web_latest(cls):
        with tempfile.TemporaryDirectory() as tmp_dir:
            dset_path = Path(tmp_dir) / "cc_maintenances_latest_dataset.json"
            helpers.download_file(config.cc_maintenances_latest_snapshot, dset_path)
            return cls.from_json(dset_path)
