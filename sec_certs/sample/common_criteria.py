import copy
import operator
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional, Set, Tuple, Union

import requests
from bs4 import Tag

from sec_certs import constants as constants
from sec_certs import helpers
from sec_certs.model.cpe_matching import CPEClassifier
from sec_certs.sample.certificate import Certificate, logger
from sec_certs.sample.protection_profile import ProtectionProfile
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.serialization.pandas import PandasSerializableType


class CommonCriteriaCert(Certificate, PandasSerializableType, ComplexSerializableType):
    cc_url = "http://www.commoncriteriaportal.org"
    empty_st_url = "http://www.commoncriteriaportal.org/files/epfiles/"

    @dataclass(eq=True, frozen=True)
    class MaintenanceReport(ComplexSerializableType):
        """
        Object for holding maintenance reports.
        """

        maintenance_date: Optional[date]
        maintenance_title: Optional[str]
        maintenance_report_link: Optional[str]
        maintenance_st_link: Optional[str]

        def __post_init__(self):
            super().__setattr__("maintenance_report_link", helpers.sanitize_link(self.maintenance_report_link))
            super().__setattr__("maintenance_st_link", helpers.sanitize_link(self.maintenance_st_link))
            super().__setattr__("maintenance_title", helpers.sanitize_string(self.maintenance_title))
            super().__setattr__("maintenance_date", helpers.sanitize_date(self.maintenance_date))

        @classmethod
        def from_dict(cls, dct: Dict) -> "CommonCriteriaCert.MaintenanceReport":
            new_dct = dct.copy()
            new_dct["maintenance_date"] = (
                date.fromisoformat(dct["maintenance_date"])
                if isinstance(dct["maintenance_date"], str)
                else dct["maintenance_date"]
            )
            return super().from_dict(new_dct)

        def __lt__(self, other):
            return self.maintenance_date < other.maintenance_date

    @dataclass(init=False)
    class InternalState(ComplexSerializableType):
        st_download_ok: bool
        report_download_ok: bool
        st_convert_ok: bool
        report_convert_ok: bool
        st_extract_ok: bool
        report_extract_ok: bool
        errors: Optional[List[str]]

        st_pdf_path: Path
        report_pdf_path: Path
        st_txt_path: Path
        report_txt_path: Path

        def __init__(
            self,
            st_download_ok: bool = True,
            report_download_ok: bool = True,
            st_convert_ok: bool = True,
            report_convert_ok: bool = True,
            st_extract_ok: bool = True,
            report_extract_ok: bool = True,
            errors: Optional[List[str]] = None,
        ):
            self.st_download_ok = st_download_ok
            self.report_download_ok = report_download_ok
            self.st_convert_ok = st_convert_ok
            self.report_convert_ok = report_convert_ok
            self.st_extract_ok = st_extract_ok
            self.report_extract_ok = report_extract_ok

            if errors is None:
                self.errors = []
            else:
                self.errors = errors

        @property
        def serialized_attributes(self) -> List[str]:
            return [
                "st_download_ok",
                "report_download_ok",
                "st_convert_ok",
                "report_convert_ok",
                "st_extract_ok",
                "report_extract_ok",
                "errors",
            ]

        def report_is_ok_to_download(self, fresh: bool = True):
            return True if fresh else not self.report_download_ok

        def st_is_ok_to_download(self, fresh: bool = True):
            return True if fresh else not self.st_download_ok

        def report_is_ok_to_convert(self, fresh: bool = True):
            return self.report_download_ok if fresh else self.report_download_ok and not self.report_convert_ok

        def st_is_ok_to_convert(self, fresh: bool = True):
            return self.st_download_ok if fresh else self.st_download_ok and not self.st_convert_ok

        def report_is_ok_to_analyze(self, fresh: bool = True):
            if fresh is True:
                return self.report_download_ok and self.report_convert_ok and self.report_extract_ok
            else:
                return self.report_download_ok and self.report_convert_ok and not self.report_extract_ok

        def st_is_ok_to_analyze(self, fresh: bool = True):
            if fresh is True:
                return self.st_download_ok and self.st_convert_ok and self.st_extract_ok
            else:
                return self.st_download_ok and self.st_convert_ok and not self.st_extract_ok

    @dataclass
    class PdfData(ComplexSerializableType):
        report_metadata: Optional[Dict[str, Any]] = field(default=None)
        st_metadata: Optional[Dict[str, Any]] = field(default=None)
        report_frontpage: Optional[Dict[str, Dict[str, Any]]] = field(default=None)
        st_frontpage: Optional[Dict[str, Dict[str, Any]]] = field(default=None)
        report_keywords: Optional[Dict[str, Any]] = field(default=None)
        st_keywords: Optional[Dict[str, Any]] = field(default=None)

        def __bool__(self):
            return any([x is not None for x in vars(self)])

        @property
        def bsi_data(self) -> Optional[Dict[str, Any]]:
            return self.report_frontpage.get("bsi", None) if self.report_frontpage else None

        @property
        def anssi_data(self) -> Optional[Dict[str, Any]]:
            return self.report_frontpage.get("anssi", None) if self.report_frontpage else None

        @property
        def cert_lab(self) -> Optional[List[str]]:
            labs = []
            if bsi_data := self.bsi_data:
                labs.append(bsi_data["cert_lab"].split(" ")[0].upper())
            if anssi_data := self.anssi_data:
                labs.append(anssi_data["cert_lab"].split(" ")[0].upper())

            return labs if labs else None

        @property
        def bsi_cert_id(self) -> Optional[str]:
            return self.bsi_data.get("cert_id", None) if self.bsi_data else None

        @property
        def anssi_cert_id(self) -> Optional[str]:
            return self.anssi_data.get("cert_id", None) if self.anssi_data else None

        @property
        def processed_cert_id(self) -> Optional[str]:
            if self.bsi_cert_id and self.anssi_cert_id:
                logger.error("Both BSI and ANSSI cert_id set.")
                raise ValueError("Both BSI and ANSSI cert_id set.")
            if self.bsi_cert_id:
                return self.bsi_cert_id
            else:
                return self.anssi_cert_id

        @property
        def keywords_rules_cert_id(self) -> Optional[Dict[str, Optional[Dict[str, Dict[str, int]]]]]:
            return self.report_keywords.get("rules_cert_id", None) if self.report_keywords else None

        @property
        def keywords_cert_id(self) -> Optional[str]:
            """
            :return: the most occuring among cert ids captured in keywords scan
            """
            if not self.keywords_rules_cert_id:
                return None

            candidates = [(x, y) for x, y in self.keywords_rules_cert_id.items()]
            candidates = sorted(candidates, key=operator.itemgetter(1), reverse=True)
            return candidates[0][0]

        @property
        def cert_id(self) -> Optional[str]:
            return processed if (processed := self.processed_cert_id) else self.keywords_cert_id

    @dataclass
    class CCHeuristics(ComplexSerializableType):
        extracted_versions: Optional[List[str]] = field(default=None)
        cpe_matches: Optional[Set[str]] = field(default=None)
        verified_cpe_matches: Optional[Set[str]] = field(default=None)
        related_cves: Optional[Set[str]] = field(default=None)
        cert_lab: Optional[List[str]] = field(default=None)
        cert_id: Optional[str] = field(default=None)
        directly_affected_by: Optional[List[str]] = field(default=None)
        indirectly_affected_by: Optional[Set[str]] = field(default=None)
        directly_affecting: Optional[Set[str]] = field(default=None)
        indirectly_affecting: Optional[Set[str]] = field(default=None)

        # manufacturer_list: Optional[List[str]]

        cpe_candidate_vendors: Optional[List[str]] = field(init=False)

        @property
        def serialized_attributes(self) -> List[str]:
            all_vars = copy.deepcopy(super().serialized_attributes)
            all_vars.remove("cpe_candidate_vendors")
            return all_vars

        def __post_init__(self):
            self.cpe_candidate_vendors = None

    pandas_columns: ClassVar[List[str]] = [
        "dgst",
        "cert_id",
        "name",
        "status",
        "category",
        "manufacturer",
        "scheme",
        "security_level",
        "not_valid_before",
        "not_valid_after",
        "report_link",
        "st_link",
        "manufacturer_web",
        "extracted_versions",
        "cpe_matches",
        "verified_cpe_matches",
        "related_cves",
        "directly_affected_by",
        "indirectly_affected_by",
        "directly_affecting",
        "indirectly_affecting",
    ]

    def __init__(
        self,
        status: str,
        category: str,
        name: str,
        manufacturer: Optional[str],
        scheme: str,
        security_level: Union[str, set],
        not_valid_before: Optional[date],
        not_valid_after: Optional[date],
        report_link: str,
        st_link: str,
        cert_link: Optional[str],
        manufacturer_web: Optional[str],
        protection_profiles: Optional[Set[ProtectionProfile]],
        maintenance_updates: Optional[Set[MaintenanceReport]],
        state: Optional[InternalState],
        pdf_data: Optional[PdfData],
        heuristics: Optional[CCHeuristics],
    ):
        super().__init__()

        self.status = status
        self.category = category
        self.name = helpers.sanitize_string(name)

        self.manufacturer = None
        if manufacturer:
            self.manufacturer = helpers.sanitize_string(manufacturer)

        self.scheme = scheme
        self.security_level = helpers.sanitize_security_levels(security_level)
        self.not_valid_before = helpers.sanitize_date(not_valid_before)
        self.not_valid_after = helpers.sanitize_date(not_valid_after)
        self.report_link = helpers.sanitize_link(report_link)
        self.st_link = helpers.sanitize_link(st_link)
        self.cert_link = helpers.sanitize_link(cert_link)
        self.manufacturer_web = helpers.sanitize_link(manufacturer_web)
        self.protection_profiles = protection_profiles
        self.maintenance_updates = maintenance_updates

        if state is None:
            state = self.InternalState()
        self.state = state

        if pdf_data is None:
            pdf_data = self.PdfData()
        self.pdf_data = pdf_data

        if heuristics is None:
            heuristics = self.CCHeuristics()
        self.heuristics = heuristics

    @property
    def dgst(self) -> str:
        """
        Computes the primary key of the sample using first 16 bytes of SHA-256 digest
        """
        if not (self.name is not None and self.report_link is not None and self.category is not None):
            raise RuntimeError("Certificate digest can't be computed, because information is missing.")
        return helpers.get_first_16_bytes_sha256(self.category + self.name + self.report_link)

    @property
    def label_studio_title(self):
        return self.name

    @property
    def pandas_tuple(self):
        return (
            self.dgst,
            self.heuristics.cert_id,
            self.name,
            self.status,
            self.category,
            self.manufacturer,
            self.scheme,
            self.security_level,
            self.not_valid_before,
            self.not_valid_after,
            self.report_link,
            self.st_link,
            self.manufacturer_web,
            self.heuristics.extracted_versions,
            self.heuristics.cpe_matches,
            self.heuristics.verified_cpe_matches,
            self.heuristics.related_cves,
            self.heuristics.directly_affected_by,
            self.heuristics.indirectly_affected_by,
            self.heuristics.directly_affecting,
            self.heuristics.indirectly_affecting,
        )

    def __str__(self):
        # TODO - if some of the values is None -> TypeError is raised
        return str(self.manufacturer) + " " + str(self.name) + " dgst: " + self.dgst

    def merge(self, other: "CommonCriteriaCert", other_source: Optional[str] = None):
        """
        Merges with other CC sample. Assuming they come from different sources, e.g., csv and html.
        Assuming that html source has better protection profiles, they overwrite CSV info
        On other values (apart from maintenances, see TODO below) the sanity checks are made.
        """
        if self != other:
            logger.warning(
                f"Attempting to merge divergent certificates: self[dgst]={self.dgst}, other[dgst]={other.dgst}"
            )

        for att, val in vars(self).items():
            if not val:
                setattr(self, att, getattr(other, att))
            elif other_source == "html" and att == "protection_profiles":
                setattr(self, att, getattr(other, att))
            elif other_source == "html" and att == "maintenance_updates":
                setattr(self, att, getattr(other, att))
            elif att == "state":
                setattr(self, att, getattr(other, att))
            else:
                if getattr(self, att) != getattr(other, att):
                    logger.warning(
                        f"When merging certificates with dgst {self.dgst}, the following mismatch occured: Attribute={att}, self[{att}]={getattr(self, att)}, other[{att}]={getattr(other, att)}"
                    )

    @classmethod
    def from_dict(cls, dct: Dict) -> "CommonCriteriaCert":
        new_dct = dct.copy()
        new_dct["maintenance_updates"] = set(dct["maintenance_updates"])
        new_dct["protection_profiles"] = set(dct["protection_profiles"])
        new_dct["not_valid_before"] = (
            date.fromisoformat(dct["not_valid_before"])
            if isinstance(dct["not_valid_before"], str)
            else dct["not_valid_before"]
        )
        new_dct["not_valid_after"] = (
            date.fromisoformat(dct["not_valid_after"])
            if isinstance(dct["not_valid_after"], str)
            else dct["not_valid_after"]
        )
        return super(cls, CommonCriteriaCert).from_dict(new_dct)

    @staticmethod
    def _html_row_get_name(cell: Tag) -> str:
        return list(cell.stripped_strings)[0]

    @staticmethod
    def _html_row_get_manufacturer(cell: Tag) -> Optional[str]:
        if lst := list(cell.stripped_strings):
            return lst[0]
        else:
            return None

    @staticmethod
    def _html_row_get_scheme(cell: Tag) -> str:
        return list(cell.stripped_strings)[0]

    @staticmethod
    def _html_row_get_security_level(cell: Tag) -> set:
        return set(cell.stripped_strings)

    @staticmethod
    def _html_row_get_manufacturer_web(cell: Tag) -> Optional[str]:
        for link in cell.find_all("a"):
            if link is not None and link.get("title") == "Vendor's web site" and link.get("href") != "http://":
                return link.get("href")
        return None

    @staticmethod
    def _html_row_get_protection_profiles(cell: Tag) -> set:
        protection_profiles = set()
        for link in list(cell.find_all("a")):
            if link.get("href") is not None and "/ppfiles/" in link.get("href"):
                protection_profiles.add(
                    ProtectionProfile(str(link.contents[0]), CommonCriteriaCert.cc_url + link.get("href"))
                )
        return protection_profiles

    @staticmethod
    def _html_row_get_date(cell: Tag) -> Optional[date]:
        text = cell.get_text()
        extracted_date = datetime.strptime(text, "%Y-%m-%d").date() if text else None
        return extracted_date

    @staticmethod
    def _html_row_get_report_st_links(cell: Tag) -> Tuple[str, str]:
        links = cell.find_all("a")
        # TODO: Exception checks
        assert links[1].get("title").startswith("Certification Report")
        assert links[2].get("title").startswith("Security Target")

        report_link = CommonCriteriaCert.cc_url + links[1].get("href")
        security_target_link = CommonCriteriaCert.cc_url + links[2].get("href")

        return report_link, security_target_link

    @staticmethod
    def _html_row_get_cert_link(cell: Tag) -> Optional[str]:
        links = cell.find_all("a")
        return CommonCriteriaCert.cc_url + links[0].get("href") if links else None

    @staticmethod
    def _html_row_get_maintenance_div(cell: Tag) -> Optional[Tag]:
        divs = cell.find_all("div")
        for d in divs:
            if d.find("div") and d.stripped_strings and list(d.stripped_strings)[0] == "Maintenance Report(s)":
                return d
        return None

    @staticmethod
    def _html_row_get_maintenance_updates(main_div: Tag) -> set:
        possible_updates = list(main_div.find_all("li"))
        maintenance_updates = set()
        for u in possible_updates:
            text = list(u.stripped_strings)[0]
            main_date = datetime.strptime(text.split(" ")[0], "%Y-%m-%d").date() if text else None
            main_title = text.split("– ")[1]
            main_report_link = None
            main_st_link = None
            links = u.find_all("a")
            for link in links:
                if link.get("title").startswith("Maintenance Report:"):
                    main_report_link = CommonCriteriaCert.cc_url + link.get("href")
                elif link.get("title").startswith("Maintenance ST"):
                    main_st_link = CommonCriteriaCert.cc_url + link.get("href")
                else:
                    logger.error("Unknown link in Maintenance part!")
            maintenance_updates.add(
                CommonCriteriaCert.MaintenanceReport(main_date, main_title, main_report_link, main_st_link)
            )
        return maintenance_updates

    @classmethod
    def from_html_row(cls, row: Tag, status: str, category: str) -> "CommonCriteriaCert":
        """
        Creates a CC sample from html row
        """

        cells = list(row.find_all("td"))
        if len(cells) != 7:
            logger.error("Unexpected number of cells in CC html row.")
            raise

        name = CommonCriteriaCert._html_row_get_name(cells[0])
        manufacturer = CommonCriteriaCert._html_row_get_manufacturer(cells[1])
        manufacturer_web = CommonCriteriaCert._html_row_get_manufacturer_web(cells[1])
        scheme = CommonCriteriaCert._html_row_get_scheme(cells[6])
        security_level = CommonCriteriaCert._html_row_get_security_level(cells[5])
        protection_profiles = CommonCriteriaCert._html_row_get_protection_profiles(cells[0])
        not_valid_before = CommonCriteriaCert._html_row_get_date(cells[3])
        not_valid_after = CommonCriteriaCert._html_row_get_date(cells[4])
        report_link, st_link = CommonCriteriaCert._html_row_get_report_st_links(cells[0])
        cert_link = CommonCriteriaCert._html_row_get_cert_link(cells[2])
        maintenance_div = CommonCriteriaCert._html_row_get_maintenance_div(cells[0])
        maintenances = (
            CommonCriteriaCert._html_row_get_maintenance_updates(maintenance_div) if maintenance_div else set()
        )

        return cls(
            status,
            category,
            name,
            manufacturer,
            scheme,
            security_level,
            not_valid_before,
            not_valid_after,
            report_link,
            st_link,
            cert_link,
            manufacturer_web,
            protection_profiles,
            maintenances,
            None,
            None,
            None,
        )

    def set_local_paths(
        self,
        report_pdf_dir: Optional[Union[str, Path]],
        st_pdf_dir: Optional[Union[str, Path]],
        report_txt_dir: Optional[Union[str, Path]],
        st_txt_dir: Optional[Union[str, Path]],
    ):
        if report_pdf_dir is not None:
            self.state.report_pdf_path = Path(report_pdf_dir) / (self.dgst + ".pdf")
        if st_pdf_dir is not None:
            self.state.st_pdf_path = Path(st_pdf_dir) / (self.dgst + ".pdf")
        if report_txt_dir is not None:
            self.state.report_txt_path = Path(report_txt_dir) / (self.dgst + ".txt")
        if st_txt_dir is not None:
            self.state.st_txt_path = Path(st_txt_dir) / (self.dgst + ".txt")

    @staticmethod
    def download_pdf_report(cert: "CommonCriteriaCert") -> "CommonCriteriaCert":
        exit_code: Union[str, int]
        if not cert.report_link:
            exit_code = "No link"
        else:
            exit_code = helpers.download_file(cert.report_link, cert.state.report_pdf_path)
        if exit_code != requests.codes.ok:
            error_msg = f"failed to download report from {cert.report_link}, code: {exit_code}"
            logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
            cert.state.report_download_ok = False
            if not cert.state.errors:
                cert.state.errors = []
            cert.state.errors.append(error_msg)
        return cert

    @staticmethod
    def download_pdf_target(cert: "CommonCriteriaCert") -> "CommonCriteriaCert":
        exit_code: Union[str, int]
        if not cert.st_link:
            exit_code = "No link"
        else:
            exit_code = helpers.download_file(cert.st_link, cert.state.st_pdf_path)
        if exit_code != requests.codes.ok:
            error_msg = f"failed to download ST from {cert.report_link}, code: {exit_code}"
            logger.error(f"Cert dgst: {cert.dgst}" + error_msg)
            cert.state.st_download_ok = False
            if not cert.state.errors:
                cert.state.errors = []
            cert.state.errors.append(error_msg)
        return cert

    @staticmethod
    def convert_report_pdf(cert: "CommonCriteriaCert") -> "CommonCriteriaCert":
        exit_code = helpers.convert_pdf_file(cert.state.report_pdf_path, cert.state.report_txt_path, ["-raw"])
        if exit_code != constants.RETURNCODE_OK:
            error_msg = "failed to convert report pdf->txt"
            logger.error(f"Cert dgst: {cert.dgst}" + error_msg)
            cert.state.report_convert_ok = False
            if not cert.state.errors:
                cert.state.errors = []
            cert.state.errors.append(error_msg)
        return cert

    @staticmethod
    def convert_target_pdf(cert: "CommonCriteriaCert") -> "CommonCriteriaCert":
        exit_code = helpers.convert_pdf_file(cert.state.st_pdf_path, cert.state.st_txt_path, ["-raw"])
        if exit_code != constants.RETURNCODE_OK:
            error_msg = "failed to convert security target pdf->txt"
            logger.error(f"Cert dgst: {cert.dgst}" + error_msg)
            cert.state.st_convert_ok = False
            if not cert.state.errors:
                cert.state.errors = []
            cert.state.errors.append(error_msg)
        return cert

    @staticmethod
    def extract_st_pdf_metadata(cert: "CommonCriteriaCert") -> "CommonCriteriaCert":
        response, cert.pdf_data.st_metadata = helpers.extract_pdf_metadata(cert.state.st_pdf_path)
        if response != constants.RETURNCODE_OK:
            cert.state.st_extract_ok = False
            if not cert.state.errors:
                cert.state.errors = []
            cert.state.errors.append(response)
        return cert

    @staticmethod
    def extract_report_pdf_metadata(cert: "CommonCriteriaCert") -> "CommonCriteriaCert":
        response, cert.pdf_data.report_metadata = helpers.extract_pdf_metadata(cert.state.report_pdf_path)
        if response != constants.RETURNCODE_OK:
            cert.state.report_extract_ok = False
            if not cert.state.errors:
                cert.state.errors = []
            cert.state.errors.append(response)
        return cert

    @staticmethod
    def extract_st_pdf_frontpage(cert: "CommonCriteriaCert") -> "CommonCriteriaCert":
        cert.pdf_data.st_frontpage = dict()

        response_anssi, cert.pdf_data.st_frontpage["anssi"] = helpers.search_only_headers_anssi(cert.state.st_txt_path)
        response_bsi, cert.pdf_data.st_frontpage["bsi"] = helpers.search_only_headers_bsi(cert.state.st_txt_path)

        if response_anssi != constants.RETURNCODE_OK:
            cert.state.st_extract_ok = False
            if not cert.state.errors:
                cert.state.errors = []
            cert.state.errors.append(response_anssi)
        if response_bsi != constants.RETURNCODE_OK:
            cert.state.st_extract_ok = False
            if not cert.state.errors:
                cert.state.errors = []
            cert.state.errors.append(response_bsi)

        return cert

    @staticmethod
    def extract_report_pdf_frontpage(cert: "CommonCriteriaCert") -> "CommonCriteriaCert":
        cert.pdf_data.report_frontpage = dict()
        response_bsi, cert.pdf_data.report_frontpage["bsi"] = helpers.search_only_headers_bsi(
            cert.state.report_txt_path
        )
        response_anssi, cert.pdf_data.report_frontpage["anssi"] = helpers.search_only_headers_anssi(
            cert.state.report_txt_path
        )

        if response_anssi != constants.RETURNCODE_OK:
            cert.state.report_extract_ok = False
            if not cert.state.errors:
                cert.state.errors = []
            cert.state.errors.append(response_anssi)
        if response_bsi != constants.RETURNCODE_OK:
            cert.state.report_extract_ok = False
            if not cert.state.errors:
                cert.state.errors = []
            cert.state.errors.append(response_bsi)

        return cert

    @staticmethod
    def extract_report_pdf_keywords(cert: "CommonCriteriaCert") -> "CommonCriteriaCert":
        response, cert.pdf_data.report_keywords = helpers.extract_keywords(cert.state.report_txt_path)
        if response != constants.RETURNCODE_OK:
            cert.state.report_extract_ok = False
        return cert

    @staticmethod
    def extract_st_pdf_keywords(cert: "CommonCriteriaCert") -> "CommonCriteriaCert":
        response, cert.pdf_data.st_keywords = helpers.extract_keywords(cert.state.st_txt_path)
        if response != constants.RETURNCODE_OK:
            cert.state.st_extract_ok = False
            if not cert.state.errors:
                cert.state.errors = []
            cert.state.errors.append(response)
        return cert

    def compute_heuristics_version(self):
        self.heuristics.extracted_versions = helpers.compute_heuristics_version(self.name)

    def compute_heuristics_cpe_vendors(self, cpe_classifier: CPEClassifier):
        # TODO: This method probably can be deleted.
        self.heuristics.cpe_candidate_vendors = cpe_classifier.get_candidate_list_of_vendors(self.manufacturer)  # type: ignore

    def compute_heuristics_cpe_match(self, cpe_classifier: CPEClassifier):
        self.heuristics.cpe_matches = cpe_classifier.predict_single_cert(self.manufacturer, self.name, self.heuristics.extracted_versions)  # type: ignore

    def compute_heuristics_cert_lab(self):
        if not self.pdf_data:
            logger.error("Cannot compute sample lab when pdf files were not processed.")
            return
        self.heuristics.cert_lab = self.pdf_data.cert_lab

    def compute_heuristics_cert_id(self):
        if not self.pdf_data:
            logger.error("Cannot compute sample id when pdf files were not processed.")
            return
        self.heuristics.cert_id = self.pdf_data.cert_id
