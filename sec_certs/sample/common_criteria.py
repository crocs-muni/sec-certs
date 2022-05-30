from __future__ import annotations

import copy
import operator
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
from functools import partial
from pathlib import Path
from typing import Any, Callable, ClassVar, Dict, List, Optional, Set, Tuple, Union

import requests
from bs4 import Tag

from sec_certs import constants as constants
from sec_certs import helpers
from sec_certs.cert_rules import SARS_IMPLIED_FROM_EAL, security_level_csv_scan
from sec_certs.sample.certificate import Certificate, Heuristics, References, logger
from sec_certs.sample.protection_profile import ProtectionProfile
from sec_certs.sample.sar import SAR
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.serialization.pandas import PandasSerializableType

HEADERS = {
    "anssi": helpers.search_only_headers_anssi,
    "bsi": helpers.search_only_headers_bsi,
    "nscib": helpers.search_only_headers_nscib,
    "niap": helpers.search_only_headers_niap,
    "canada": helpers.search_only_headers_canada,
}


class DependencyType(Enum):
    DIRECT = "direct"
    INDIRECT = "indirect"


class CommonCriteriaCert(
    Certificate["CommonCriteriaCert", "CommonCriteriaCert.CCHeuristics"],
    PandasSerializableType,
    ComplexSerializableType,
):
    """
    Data structure for common criteria certificate. Contains several inner classes that layer the data logic.
    Can be serialized into/from json (`ComplexSerializableType`) or pandas (`PandasSerializableType)`.
    Is basic element of `CCDataset`. The functionality is mostly related to holding data and transformations that
    the certificate can handle itself. `CCDataset` class then instrument this functionality.
    """

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
        def from_dict(cls, dct: Dict) -> CommonCriteriaCert.MaintenanceReport:
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
        """
        Holds internal state of the dataset, whether downloads and converts of individual components succeeded. Also
        holds information about errors and paths to the files.
        """

        st_download_ok: bool
        report_download_ok: bool
        st_convert_ok: bool
        report_convert_ok: bool
        st_extract_ok: bool
        report_extract_ok: bool
        errors: List[str]

        st_pdf_path: Path
        report_pdf_path: Path
        st_pdf_hash: Optional[str]
        report_pdf_hash: Optional[str]
        st_txt_path: Path
        report_txt_path: Path
        st_txt_hash: Optional[str]
        report_txt_hash: Optional[str]

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
            self.errors = errors if errors else []

        @property
        def serialized_attributes(self) -> List[str]:
            return [
                "st_download_ok",
                "report_download_ok",
                "st_pdf_hash",
                "report_pdf_hash",
                "st_convert_ok",
                "report_convert_ok",
                "st_txt_hash",
                "report_txt_hash",
                "st_extract_ok",
                "report_extract_ok",
                "errors",
            ]

        def report_is_ok_to_download(self, fresh: bool = True) -> bool:
            return True if fresh else not self.report_download_ok

        def st_is_ok_to_download(self, fresh: bool = True) -> bool:
            return True if fresh else not self.st_download_ok

        def report_is_ok_to_convert(self, fresh: bool = True) -> bool:
            return self.report_download_ok if fresh else self.report_download_ok and not self.report_convert_ok

        def st_is_ok_to_convert(self, fresh: bool = True) -> bool:
            return self.st_download_ok if fresh else self.st_download_ok and not self.st_convert_ok

        def report_is_ok_to_analyze(self, fresh: bool = True) -> bool:
            if fresh is True:
                return self.report_download_ok and self.report_convert_ok and self.report_extract_ok
            else:
                return self.report_download_ok and self.report_convert_ok and not self.report_extract_ok

        def st_is_ok_to_analyze(self, fresh: bool = True) -> bool:
            if fresh is True:
                return self.st_download_ok and self.st_convert_ok and self.st_extract_ok
            else:
                return self.st_download_ok and self.st_convert_ok and not self.st_extract_ok

    @dataclass
    class PdfData(ComplexSerializableType):
        """
        Class that holds data extracted from pdf files.
        """

        report_metadata: Optional[Dict[str, Any]] = field(default=None)
        st_metadata: Optional[Dict[str, Any]] = field(default=None)
        report_frontpage: Optional[Dict[str, Dict[str, Any]]] = field(default=None)
        st_frontpage: Optional[Dict[str, Dict[str, Any]]] = field(default=None)
        report_keywords: Optional[Dict[str, Any]] = field(default=None)
        st_keywords: Optional[Dict[str, Any]] = field(default=None)

        def __bool__(self) -> bool:
            return any([x is not None for x in vars(self)])

        @property
        def bsi_data(self) -> Optional[Dict[str, Any]]:
            """
            Returns frontpage data related to BSI-provided information
            """
            return self.report_frontpage.get("bsi", None) if self.report_frontpage else None

        @property
        def niap_data(self) -> Optional[Dict[str, Any]]:
            """
            Returns frontpage data related to niap-provided information
            """
            return self.report_frontpage.get("niap", None) if self.report_frontpage else None

        @property
        def nscib_data(self) -> Optional[Dict[str, Any]]:
            """
            Returns frontpage data related to nscib-provided information
            """
            return self.report_frontpage.get("nscib", None) if self.report_frontpage else None

        @property
        def canada_data(self) -> Optional[Dict[str, Any]]:
            """
            Returns frontpage data related to canada-provided information
            """
            return self.report_frontpage.get("canada", None) if self.report_frontpage else None

        @property
        def anssi_data(self) -> Optional[Dict[str, Any]]:
            """
            Returns frontpage data related to ANSSI-provided information
            """
            return self.report_frontpage.get("anssi", None) if self.report_frontpage else None

        @property
        def cert_lab(self) -> Optional[List[str]]:
            """
            Returns labs for which certificate data was parsed.
            """
            labs = [
                data["cert_lab"].split(" ")[0].upper()
                for data in [self.bsi_data, self.anssi_data, self.niap_data, self.nscib_data, self.canada_data]
                if data
            ]
            return labs if labs else None

        @property
        def bsi_cert_id(self) -> Optional[str]:
            return self.bsi_data.get("cert_id", None) if self.bsi_data else None

        @property
        def niap_cert_id(self) -> Optional[str]:
            return self.niap_data.get("cert_id", None) if self.niap_data else None

        @property
        def nscib_cert_id(self) -> Optional[str]:
            return self.nscib_data.get("cert_id", None) if self.nscib_data else None

        @property
        def canada_cert_id(self) -> Optional[str]:
            return self.canada_data.get("cert_id", None) if self.canada_data else None

        @property
        def anssi_cert_id(self) -> Optional[str]:
            return self.anssi_data.get("cert_id", None) if self.anssi_data else None

        @property
        def processed_cert_id(self) -> Optional[str]:
            """
            Returns processed cert id extracted from the pdf data.
            """
            cert_ids = set(
                filter(
                    lambda x: x,
                    {self.bsi_cert_id, self.niap_cert_id, self.nscib_cert_id, self.canada_cert_id, self.anssi_cert_id},
                )
            )
            # Expect only one cert_id in the set above.
            if len(cert_ids) >= 2:
                raise ValueError("More than one cert_id set.")
            elif len(cert_ids) == 1:
                return cert_ids.pop()
            else:
                return None

        @property
        def keywords_rules_cert_id(self) -> Optional[Dict[str, Optional[Dict[str, Dict[str, int]]]]]:
            return self.report_keywords.get("rules_cert_id", None) if self.report_keywords else None

        @property
        def keywords_cert_id(self) -> Optional[str]:
            """
            Returns the most frequently appearing cert id. If you don't know why to use this, you should probably use
            `cert_id` property.
            """
            if not self.keywords_rules_cert_id:
                return None

            candidates = [(x, y) for x, y in self.keywords_rules_cert_id.items()]
            candidates = sorted(candidates, key=operator.itemgetter(1), reverse=True)
            return candidates[0][0]

        @property
        def cert_id(self) -> Optional[str]:
            """
            Returns `processed_cert_id` if it exists, else return `keyword_cert_id`
            """
            return self.processed_cert_id if self.processed_cert_id else self.keywords_cert_id

    @dataclass
    class CCHeuristics(Heuristics, ComplexSerializableType):
        """
        Class for various heuristics related to CommonCriteriaCert
        """

        extracted_versions: Optional[Set[str]] = field(default=None)
        cpe_matches: Optional[Set[str]] = field(default=None)
        verified_cpe_matches: Optional[Set[str]] = field(default=None)
        related_cves: Optional[Set[str]] = field(default=None)
        cert_lab: Optional[List[str]] = field(default=None)
        cert_id: Optional[str] = field(default=None)
        st_references: References = field(default_factory=References)
        report_references: References = field(default_factory=References)
        extracted_sars: Optional[Set[SAR]] = field(default=None)
        direct_dependency_cves: Optional[Set[str]] = field(default=None)
        indirect_dependency_cves: Optional[Set[str]] = field(default=None)

        @property
        def serialized_attributes(self) -> List[str]:
            return copy.deepcopy(super().serialized_attributes)

    pandas_columns: ClassVar[List[str]] = [
        "dgst",
        "cert_id",
        "name",
        "status",
        "category",
        "manufacturer",
        "scheme",
        "security_level",
        "eal",
        "not_valid_before",
        "not_valid_after",
        "report_link",
        "st_link",
        "manufacturer_web",
        "extracted_versions",
        "cpe_matches",
        "verified_cpe_matches",
        "related_cves",
        "directly_referenced_by",
        "indirectly_referenced_by",
        "directly_referencing",
        "indirectly_referencing",
        "extracted_sars",
    ]

    def __init__(
        self,
        status: str,
        category: str,
        name: str,
        manufacturer: Optional[str],
        scheme: str,
        security_level: Union[str, Set[str]],
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
        self.state = self.InternalState() if not state else state
        self.pdf_data = self.PdfData() if not pdf_data else pdf_data
        self.heuristics: CommonCriteriaCert.CCHeuristics = self.CCHeuristics() if not heuristics else heuristics

    @property
    def dgst(self) -> str:
        """
        Computes the primary key of the sample using first 16 bytes of SHA-256 digest
        """
        if not (self.name is not None and self.report_link is not None and self.category is not None):
            raise RuntimeError("Certificate digest can't be computed, because information is missing.")
        return helpers.get_first_16_bytes_sha256(self.category + self.name + self.report_link)

    @property
    def eal(self) -> Optional[str]:
        """
        Returns EAL of certificate if it was extracted, None otherwise.
        """
        res = [x for x in self.security_level if re.match(security_level_csv_scan, x)]
        if not res:
            return None

        if not len(res) == 1:
            raise ValueError(f"Expected single EAL in security_level field, got: {res}")
        return res[0]

    @property
    def actual_sars(self) -> Optional[Set[SAR]]:
        """
        Computes actual SARs. First, SARs implied by EAL are computed. Then, these are augmented with heuristically extracted SARs
        :return Optional[Set[SAR]]: Set of actual SARs of a certificate, None if empty
        """
        sars = dict()
        if self.eal:
            sars = {x[0]: SAR(x[0], x[1]) for x in SARS_IMPLIED_FROM_EAL[self.eal[:4]]}

        if self.heuristics.extracted_sars:
            for sar in self.heuristics.extracted_sars:
                if sar not in sars or sar.level > sars[sar.family].level:
                    sars[sar.family] = sar

        return set(sars.values()) if sars else None

    @property
    def label_studio_title(self) -> Optional[str]:
        return self.name

    @property
    def pandas_tuple(self) -> Tuple:
        """
        Returns tuple of attributes meant for pandas serialization
        """
        return (
            self.dgst,
            self.heuristics.cert_id,
            self.name,
            self.status,
            self.category,
            self.manufacturer,
            self.scheme,
            self.security_level,
            self.eal,
            self.not_valid_before,
            self.not_valid_after,
            self.report_link,
            self.st_link,
            self.manufacturer_web,
            self.heuristics.extracted_versions,
            self.heuristics.cpe_matches,
            self.heuristics.verified_cpe_matches,
            self.heuristics.related_cves,
            self.heuristics.report_references.directly_referenced_by,
            self.heuristics.report_references.indirectly_referenced_by,
            self.heuristics.report_references.directly_referencing,
            self.heuristics.report_references.indirectly_referencing,
            self.heuristics.extracted_sars,
        )

    def __str__(self) -> str:
        printed_manufacturer = self.manufacturer if self.manufacturer else "Unknown manufacturer"
        return str(printed_manufacturer) + " " + str(self.name) + " dgst: " + self.dgst

    def merge(self, other: CommonCriteriaCert, other_source: Optional[str] = None) -> None:
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
    def from_dict(cls, dct: Dict) -> CommonCriteriaCert:
        """
        Deserializes dictionary into `CommonCriteriaCert`
        """
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
    def _html_row_get_maintenance_updates(main_div: Tag) -> Set[CommonCriteriaCert.MaintenanceReport]:
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
    def from_html_row(cls, row: Tag, status: str, category: str) -> CommonCriteriaCert:
        """
        Creates a CC sample from html row of commoncriteria.org webpage.
        """

        cells = list(row.find_all("td"))
        if len(cells) != 7:
            raise ValueError(f"Unexpected number of <td> elements in CC html row. Expected: 7, actual: {len(cells)}")

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
    ) -> None:
        """
        Sets paths to files given the requested directories

        :param Optional[Union[str, Path]] report_pdf_dir: Directory where pdf reports shall be stored
        :param Optional[Union[str, Path]] st_pdf_dir: Directory where pdf security targets shall be stored
        :param Optional[Union[str, Path]] report_txt_dir: Directory where txt reports shall be stored
        :param Optional[Union[str, Path]] st_txt_dir: Directory where txt security targets shall be stored
        """
        if report_pdf_dir is not None:
            self.state.report_pdf_path = Path(report_pdf_dir) / (self.dgst + ".pdf")
        if st_pdf_dir is not None:
            self.state.st_pdf_path = Path(st_pdf_dir) / (self.dgst + ".pdf")
        if report_txt_dir is not None:
            self.state.report_txt_path = Path(report_txt_dir) / (self.dgst + ".txt")
        if st_txt_dir is not None:
            self.state.st_txt_path = Path(st_txt_dir) / (self.dgst + ".txt")

    @staticmethod
    def download_pdf_report(cert: CommonCriteriaCert) -> CommonCriteriaCert:
        """
        Downloads pdf of certification report given the certificate. Staticmethod to allow for parallelization.

        :param CommonCriteriaCert cert: cert to download the pdf report for
        :return CommonCriteriaCert: returns the modified certificate with updated state
        """
        exit_code: Union[str, int]
        if not cert.report_link:
            exit_code = "No link"
        else:
            exit_code = helpers.download_file(cert.report_link, cert.state.report_pdf_path)
        if exit_code != requests.codes.ok:
            error_msg = f"failed to download report from {cert.report_link}, code: {exit_code}"
            logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
            cert.state.report_download_ok = False
            cert.state.errors.append(error_msg)
        else:
            cert.state.report_pdf_hash = helpers.get_sha256_filepath(cert.state.report_pdf_path)
        return cert

    @staticmethod
    def download_pdf_st(cert: CommonCriteriaCert) -> CommonCriteriaCert:
        """
        Downloads pdf of security target given the certificate. Staticmethod to allow for parallelization.

        :param CommonCriteriaCert cert: cert to download the pdf security target for
        :return CommonCriteriaCert: returns the modified certificate with updated state
        """
        exit_code: Union[str, int]
        if not cert.st_link:
            exit_code = "No link"
        else:
            exit_code = helpers.download_file(cert.st_link, cert.state.st_pdf_path)
        if exit_code != requests.codes.ok:
            error_msg = f"failed to download ST from {cert.report_link}, code: {exit_code}"
            logger.error(f"Cert dgst: {cert.dgst}" + error_msg)
            cert.state.st_download_ok = False
            cert.state.errors.append(error_msg)
        else:
            cert.state.st_pdf_hash = helpers.get_sha256_filepath(cert.state.st_pdf_path)
        return cert

    @staticmethod
    def convert_report_pdf(cert: CommonCriteriaCert) -> CommonCriteriaCert:
        """
        Converts the pdf certification report to txt, given the certificate. Staticmethod to allow for parallelization.

        :param CommonCriteriaCert cert: cert to download the pdf report for
        :return CommonCriteriaCert: the modified certificate with updated state
        """
        exit_code = helpers.convert_pdf_file(cert.state.report_pdf_path, cert.state.report_txt_path)
        if exit_code != constants.RETURNCODE_OK:
            error_msg = "failed to convert report pdf->txt"
            logger.error(f"Cert dgst: {cert.dgst}" + error_msg)
            cert.state.report_convert_ok = False
            cert.state.errors.append(error_msg)
        else:
            cert.state.report_txt_hash = helpers.get_sha256_filepath(cert.state.report_txt_path)
        return cert

    @staticmethod
    def convert_st_pdf(cert: CommonCriteriaCert) -> CommonCriteriaCert:
        """
        Converts the pdf security target to txt, given the certificate. Staticmethod to allow for parallelization.

        :param CommonCriteriaCert cert: cert to download the pdf security target for
        :return CommonCriteriaCert: the modified certificate with updated state
        """
        exit_code = helpers.convert_pdf_file(cert.state.st_pdf_path, cert.state.st_txt_path)
        if exit_code != constants.RETURNCODE_OK:
            error_msg = "failed to convert security target pdf->txt"
            logger.error(f"Cert dgst: {cert.dgst}" + error_msg)
            cert.state.st_convert_ok = False
            cert.state.errors.append(error_msg)
        else:
            cert.state.st_txt_hash = helpers.get_sha256_filepath(cert.state.st_txt_path)
        return cert

    @staticmethod
    def extract_st_pdf_metadata(cert: CommonCriteriaCert) -> CommonCriteriaCert:
        """
        Extracts metadata from security target pdf given the certificate. Staticmethod to allow for parallelization.

        :param CommonCriteriaCert cert: cert to extract the metadata for.
        :return CommonCriteriaCert: the modified certificate with updated state
        """
        response, cert.pdf_data.st_metadata = helpers.extract_pdf_metadata(cert.state.st_pdf_path)
        if response != constants.RETURNCODE_OK:
            cert.state.st_extract_ok = False
            cert.state.errors.append(response)
        return cert

    @staticmethod
    def extract_report_pdf_metadata(cert: CommonCriteriaCert) -> CommonCriteriaCert:
        """
        Extracts metadata from certification report pdf given the certificate. Staticmethod to allow for parallelization.

        :param CommonCriteriaCert cert: cert to extract the metadata for.
        :return CommonCriteriaCert: the modified certificate with updated state
        """
        response, cert.pdf_data.report_metadata = helpers.extract_pdf_metadata(cert.state.report_pdf_path)
        if response != constants.RETURNCODE_OK:
            cert.state.report_extract_ok = False
            cert.state.errors.append(response)
        return cert

    @staticmethod
    def extract_st_pdf_frontpage(cert: CommonCriteriaCert) -> CommonCriteriaCert:
        """
        Extracts data from security target pdf frontpage given the certificate. Staticmethod to allow for parallelization.

        :param CommonCriteriaCert cert: cert to extract the frontpage data for.
        :return CommonCriteriaCert: the modified certificate with updated state
        """
        cert.pdf_data.st_frontpage = {}

        for header_type, associated_header_func in HEADERS.items():
            response, cert.pdf_data.st_frontpage[header_type] = associated_header_func(cert.state.st_txt_path)

            if response != constants.RETURNCODE_OK:
                cert.state.st_extract_ok = False
                if not cert.state.errors:
                    cert.state.errors = []
                cert.state.errors.append(response)

        return cert

    @staticmethod
    def extract_report_pdf_frontpage(cert: CommonCriteriaCert) -> CommonCriteriaCert:
        """
        Extracts data from certification report pdf frontpage given the certificate. Staticmethod to allow for parallelization.

        :param CommonCriteriaCert cert: cert to extract the frontpage data for.
        :return CommonCriteriaCert: the modified certificate with updated state
        """
        cert.pdf_data.report_frontpage = {}

        for header_type, associated_header_func in HEADERS.items():
            response, cert.pdf_data.report_frontpage[header_type] = associated_header_func(cert.state.report_txt_path)

            if response != constants.RETURNCODE_OK:
                cert.state.report_extract_ok = False
                if not cert.state.errors:
                    cert.state.errors = []
                cert.state.errors.append(response)

        return cert

    @staticmethod
    def extract_report_pdf_keywords(cert: CommonCriteriaCert) -> CommonCriteriaCert:
        """
        Matches regular expresions in txt obtained from certification report and extracts the matches into attribute.
        Static method to allow for parallelization

        :param CommonCriteriaCert cert: certificate to extract the keywords for.
        :return CommonCriteriaCert: the modified certificate with extracted keywords.
        """
        response, cert.pdf_data.report_keywords = helpers.extract_keywords(cert.state.report_txt_path)
        if response != constants.RETURNCODE_OK:
            cert.state.report_extract_ok = False
        return cert

    @staticmethod
    def extract_st_pdf_keywords(cert: CommonCriteriaCert) -> CommonCriteriaCert:
        """
        Matches regular expresions in txt obtained from security target and extracts the matches into attribute.
        Static method to allow for parallelization

        :param CommonCriteriaCert cert: certificate to extract the keywords for.
        :return CommonCriteriaCert: the modified certificate with extracted keywords.
        """
        response, cert.pdf_data.st_keywords = helpers.extract_keywords(cert.state.st_txt_path)
        if response != constants.RETURNCODE_OK:
            cert.state.st_extract_ok = False
            cert.state.errors.append(response)
        return cert

    def compute_heuristics_version(self) -> None:
        """
        Fills in the heuristically obtained version of certified product into attribute in heuristics class.
        """
        self.heuristics.extracted_versions = helpers.compute_heuristics_version(self.name) if self.name else set()

    def compute_heuristics_cert_lab(self) -> None:
        """
        Fills in the heuristically obtained evaluation laboratory into attribute in heuristics class.
        """
        if not self.pdf_data:
            logger.error("Cannot compute sample lab when pdf files were not processed.")
            return
        self.heuristics.cert_lab = self.pdf_data.cert_lab

    def compute_heuristics_cert_id(self, all_cert_ids: Set[str]):
        """
        Given list of cert ids from the whole dataset, will normalize own cert id into canonical form

        :param Set[str] all_cert_ids: cert ids from the whole dataset.
        """
        if not self.pdf_data:
            logger.warning("Cannot compute sample id when pdf files were not processed.")
            return
        self.heuristics.cert_id = self.pdf_data.cert_id
        self.normalize_cert_id(all_cert_ids)

    @staticmethod
    def _is_anssi_cert(cert_id: str) -> bool:
        return cert_id.startswith("ANSS")

    @staticmethod
    def _fix_anssi_cert_id(cert_id: str) -> str:
        new_cert_id = cert_id

        if new_cert_id.startswith("ANSSi"):  # mistyped ANSSi
            new_cert_id = "ANSSI" + new_cert_id[4:]

        # Bug - getting out of index - ANSSI-2009/30
        # TMP solution
        # TODO: Fix me, @georgefi
        if len(new_cert_id) >= len("ANSSI-CC-0000") + 1:
            if (
                new_cert_id[len("ANSSI-CC-0000")] == "_"
            ):  # _ instead of / after year (ANSSI-CC-2010_40 -> ANSSI-CC-2010/40)
                new_cert_id = new_cert_id[: len("ANSSI-CC-0000")] + "/" + new_cert_id[len("ANSSI-CC-0000") + 1 :]

        if "_" in new_cert_id:  # _ instead of -
            new_cert_id = new_cert_id.replace("_", "-")

        return new_cert_id

    @staticmethod
    def _is_bsi_cert(cert_id: str) -> bool:
        return cert_id.startswith("BSI-DSZ-CC-")

    @staticmethod
    def _extract_bsi_parts(bsi_parts: List[str]) -> Tuple:
        cert_num = None
        cert_version = None
        cert_year = None

        if len(bsi_parts) > 3:
            cert_num = bsi_parts[3]
        if len(bsi_parts) > 4:
            if bsi_parts[4].startswith("V") or bsi_parts[4].startswith("v"):
                cert_version = bsi_parts[4].upper()  # get version in uppercase
            else:
                cert_year = bsi_parts[4]
        if len(bsi_parts) > 5:
            cert_year = bsi_parts[5]

        return cert_num, cert_version, cert_year

    @staticmethod
    def _fix_bsi_cert_id(cert_id: str, all_cert_ids: Set[str]) -> str:
        start_year = 1996
        limit_year = datetime.now().year + 1
        bsi_parts = cert_id.split("-")

        cert_num, cert_version, cert_year = CommonCriteriaCert._extract_bsi_parts(bsi_parts)
        if cert_year is None:
            for year in range(start_year, limit_year):
                cert_id_possible = cert_id + "-" + str(year)

                if cert_id_possible in all_cert_ids:
                    # we found version with year
                    cert_year = str(year)
                    break

        # reconstruct BSI number again
        new_cert_id = "BSI-DSZ-CC"
        if cert_num is not None:
            new_cert_id += "-" + cert_num
        if cert_version is not None:
            new_cert_id += "-" + cert_version
        if cert_year is not None:
            new_cert_id += "-" + cert_year

        return new_cert_id

    @staticmethod
    def _is_spain_cert_id(cert_id: str) -> bool:
        return "-INF-" in cert_id

    @staticmethod
    def _fix_spain_cert_id(cert_id: str) -> str:
        spain_parts = cert_id.split("-")
        cert_year = spain_parts[0]
        cert_batch = spain_parts[1]
        cert_num = spain_parts[3]

        if "v" in cert_num:
            cert_num = cert_num[: cert_num.find("v")]
        if "V" in cert_num:
            cert_num = cert_num[: cert_num.find("V")]

        new_cert_id = f"{cert_year}-{cert_batch}-INF-{cert_num}"  # drop version

        return new_cert_id

    @staticmethod
    def _is_ocsi_cert_id(cert_id: str) -> bool:
        return "OCSI/CERT" in cert_id

    @staticmethod
    def _fix_ocsi_cert_id(cert_id: str) -> str:
        new_cert_id = cert_id
        if not new_cert_id.endswith("/RC"):
            new_cert_id = cert_id + "/RC"

        return new_cert_id

    def _get_cert_laboratory(self) -> str:
        if not self.heuristics.cert_id:
            raise ValueError("Cert ID was None but cert laboratory was to be computed based on its value.")
        cert_id = self.heuristics.cert_id.strip()

        if CommonCriteriaCert._is_anssi_cert(cert_id):
            return "anssi"

        if CommonCriteriaCert._is_bsi_cert(cert_id):
            return "bsi"

        if CommonCriteriaCert._is_spain_cert_id(cert_id):
            return "spain"

        if CommonCriteriaCert._is_ocsi_cert_id(cert_id):
            return "ocsi"

        return "unknown"

    def normalize_cert_id(self, all_cert_ids: Set[str]) -> None:
        """
        Attempts to find certification laboratory and transform certificate id into canonical form. This is achieved
        also by comparisons to all other cert ids in the dataset.

        :param Set[str] all_cert_ids: set of all cert ids in the dataset.
        """
        fix_methods: Dict[str, Callable] = {
            "anssi": CommonCriteriaCert._fix_anssi_cert_id,
            "bsi": partial(CommonCriteriaCert._fix_bsi_cert_id, all_cert_ids=all_cert_ids),
            "spain": CommonCriteriaCert._fix_spain_cert_id,
            "ocsi": CommonCriteriaCert._fix_ocsi_cert_id,
        }

        try:
            cert_lab = self._get_cert_laboratory()
        except ValueError:
            return None

        # No need for any fix, bcs we do not know how
        if cert_lab == "unknown":
            return None

        self.heuristics.cert_id = fix_methods[cert_lab](self.pdf_data.cert_id)
