from __future__ import annotations

import copy
import re
from collections import ChainMap, Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import unquote_plus, urlparse

import numpy as np
import requests
from bs4 import Tag

import sec_certs.utils.extract
import sec_certs.utils.pdf
import sec_certs.utils.sanitization
from sec_certs import constants as constants
from sec_certs.cert_rules import (
    PANDAS_KEYWORDS_CATEGORIES,
    SARS_IMPLIED_FROM_EAL,
    cc_rules,
    rules,
    security_level_csv_scan,
)
from sec_certs.sample.cc_certificate_id import canonicalize
from sec_certs.sample.certificate import Certificate
from sec_certs.sample.certificate import Heuristics as BaseHeuristics
from sec_certs.sample.certificate import References, logger
from sec_certs.sample.protection_profile import ProtectionProfile
from sec_certs.sample.sar import SAR
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.serialization.pandas import PandasSerializableType
from sec_certs.utils import helpers
from sec_certs.utils.extract import normalize_match_string

HEADERS = {
    "anssi": sec_certs.utils.extract.search_only_headers_anssi,
    "bsi": sec_certs.utils.extract.search_only_headers_bsi,
    "nscib": sec_certs.utils.extract.search_only_headers_nscib,
    "niap": sec_certs.utils.extract.search_only_headers_niap,
    "canada": sec_certs.utils.extract.search_only_headers_canada,
}


class DependencyType(Enum):
    DIRECT = "direct"
    INDIRECT = "indirect"


class CommonCriteriaCert(
    Certificate["CommonCriteriaCert", "CommonCriteriaCert.Heuristics"],
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
            super().__setattr__(
                "maintenance_report_link", sec_certs.utils.sanitization.sanitize_link(self.maintenance_report_link)
            )
            super().__setattr__(
                "maintenance_st_link", sec_certs.utils.sanitization.sanitize_link(self.maintenance_st_link)
            )
            super().__setattr__(
                "maintenance_title", sec_certs.utils.sanitization.sanitize_string(self.maintenance_title)
            )
            super().__setattr__("maintenance_date", sec_certs.utils.sanitization.sanitize_date(self.maintenance_date))

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
        Holds internal state of the certificate, whether downloads and converts of individual components succeeded. Also
        holds information about errors and paths to the files.
        """

        st_download_ok: bool  # Whether target download went OK
        report_download_ok: bool  # Whether report download went OK
        st_convert_garbage: bool  # Whether initial target conversion resulted in garbage
        report_convert_garbage: bool  # Whether initial report conversion resulted in garbage
        st_convert_ok: bool  # Whether overall target conversion went OK (either pdftotext or via OCR)
        report_convert_ok: bool  # Whether overall report conversion went OK (either pdftotext or via OCR)
        st_extract_ok: bool  # Whether target extraction went OK
        report_extract_ok: bool  # Whether report extraction went OK

        errors: List[str]

        st_pdf_hash: Optional[str]
        report_pdf_hash: Optional[str]
        st_txt_hash: Optional[str]
        report_txt_hash: Optional[str]

        st_pdf_path: Path
        report_pdf_path: Path
        st_txt_path: Path
        report_txt_path: Path

        def __init__(
            self,
            st_download_ok: bool = False,
            report_download_ok: bool = False,
            st_convert_garbage: bool = False,
            report_convert_garbage: bool = False,
            st_convert_ok: bool = False,
            report_convert_ok: bool = False,
            st_extract_ok: bool = False,
            report_extract_ok: bool = False,
            errors: Optional[List[str]] = None,
            st_pdf_hash: Optional[str] = None,
            report_pdf_hash: Optional[str] = None,
            st_txt_hash: Optional[str] = None,
            report_txt_hash: Optional[str] = None,
        ):
            super().__init__()
            self.st_download_ok = st_download_ok
            self.report_download_ok = report_download_ok
            self.st_convert_garbage = st_convert_garbage
            self.report_convert_garbage = report_convert_garbage
            self.st_convert_ok = st_convert_ok
            self.report_convert_ok = report_convert_ok
            self.st_extract_ok = st_extract_ok
            self.report_extract_ok = report_extract_ok
            self.errors = errors if errors else []
            self.st_pdf_hash = st_pdf_hash
            self.report_pdf_hash = report_pdf_hash
            self.st_txt_hash = st_txt_hash
            self.report_txt_hash = report_txt_hash

        @property
        def serialized_attributes(self) -> List[str]:
            return [
                "st_download_ok",
                "report_download_ok",
                "st_convert_garbage",
                "report_convert_garbage",
                "st_convert_ok",
                "report_convert_ok",
                "st_extract_ok",
                "report_extract_ok",
                "errors",
                "st_pdf_hash",
                "report_pdf_hash",
                "st_txt_hash",
                "report_txt_hash",
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
                return self.report_download_ok and self.report_convert_ok
            else:
                return self.report_download_ok and self.report_convert_ok and not self.report_extract_ok

        def st_is_ok_to_analyze(self, fresh: bool = True) -> bool:
            if fresh is True:
                return self.st_download_ok and self.st_convert_ok
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
        report_filename: Optional[str] = field(default=None)
        st_filename: Optional[str] = field(default=None)

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

        def frontpage_cert_id(self, scheme: str) -> Dict[str, float]:
            """
            Get cert_id candidate from the frontpage of the report.
            """
            scheme_map = {
                "DE": self.bsi_cert_id,
                "US": self.niap_cert_id,
                "NL": self.nscib_cert_id,
                "CA": self.canada_cert_id,
                "FR": self.anssi_cert_id,
            }
            if scheme in scheme_map and (candidate := scheme_map[scheme]):
                return {candidate: 1.0}
            return {}

        def filename_cert_id(self, scheme: str) -> Dict[str, float]:
            """
            Get cert_id candidates from the matches in the report filename.
            """
            if not self.report_filename:
                return {}
            scheme_rules = rules["cc_cert_id"][scheme]
            matches: Counter = Counter()
            for rule in scheme_rules:
                match = re.search(rule, self.report_filename)
                if match:
                    cert_id = normalize_match_string(match.group())
                    matches[cert_id] += 1
            if not matches:
                return {}
            total = max(matches.values())
            results = {}
            for candidate, count in matches.items():
                results[candidate] = count / total
            # TODO count length in weight
            return results

        def keywords_cert_id(self, scheme: str) -> Dict[str, float]:
            """
            Get cert_id candidates from the keywords matches in the report.
            """
            if not self.report_keywords:
                return {}
            cert_id_matches = self.report_keywords.get("cc_cert_id")
            if not cert_id_matches:
                return {}

            if scheme not in cert_id_matches:
                return {}
            matches: Counter = Counter(cert_id_matches[scheme])
            if not matches:
                return {}
            total = max(matches.values())
            results = {}
            for candidate, count in matches.items():
                results[candidate] = count / total
            # TODO count length in weight
            return results

        def metadata_cert_id(self, scheme: str) -> Dict[str, float]:
            """
            Get cert_id candidates from the report metadata.
            """
            scheme_rules = rules["cc_cert_id"][scheme]
            fields = ("/Title", "/Subject")
            matches: Counter = Counter()
            for meta_field in fields:
                field_val = self.report_metadata.get(meta_field) if self.report_metadata else None
                if not field_val:
                    continue
                for rule in scheme_rules:
                    match = re.search(rule, field_val)
                    if match:
                        cert_id = normalize_match_string(match.group())
                        matches[cert_id] += 1
            if not matches:
                return {}
            total = max(matches.values())
            results = {}
            for candidate, count in matches.items():
                results[candidate] = count / total
            # TODO count length in weight
            return results

        def candidate_cert_ids(self, scheme: str) -> Dict[str, float]:
            frontpage_id = self.frontpage_cert_id(scheme)
            metadata_id = self.metadata_cert_id(scheme)
            filename_id = self.filename_cert_id(scheme)
            keywords_id = self.keywords_cert_id(scheme)

            # Join them and weigh them, each is normalized with weights from 0 to 1 (if anything is returned)
            candidates: Dict[str, float] = defaultdict(lambda: 0.0)
            # TODO: Add heuristic based on ordering of ids (and extracted year + increment)
            # TODO: Add heuristic based on length
            for candidate, count in frontpage_id.items():
                candidates[canonicalize(candidate, scheme)] += count * 1.5
            for candidate, count in metadata_id.items():
                candidates[canonicalize(candidate, scheme)] += count * 1.2
            for candidate, count in keywords_id.items():
                candidates[canonicalize(candidate, scheme)] += count * 1.0
            for candidate, count in filename_id.items():
                candidates[canonicalize(candidate, scheme)] += count * 1.0
            return candidates

    @dataclass
    class Heuristics(BaseHeuristics, ComplexSerializableType):
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
        "cert_link",
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
        "protection_profiles",
        "cert_lab",
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
        heuristics: Optional[Heuristics],
    ):
        super().__init__()

        self.status = status
        self.category = category
        self.name = sec_certs.utils.sanitization.sanitize_string(name)

        self.manufacturer = None
        if manufacturer:
            self.manufacturer = sec_certs.utils.sanitization.sanitize_string(manufacturer)

        self.scheme = scheme
        self.security_level = sec_certs.utils.sanitization.sanitize_security_levels(security_level)
        self.not_valid_before = sec_certs.utils.sanitization.sanitize_date(not_valid_before)
        self.not_valid_after = sec_certs.utils.sanitization.sanitize_date(not_valid_after)
        self.report_link = sec_certs.utils.sanitization.sanitize_link(report_link)
        self.st_link = sec_certs.utils.sanitization.sanitize_link(st_link)
        self.cert_link = sec_certs.utils.sanitization.sanitize_link(cert_link)
        self.manufacturer_web = sec_certs.utils.sanitization.sanitize_link(manufacturer_web)
        self.protection_profiles = protection_profiles
        self.maintenance_updates = maintenance_updates
        self.state = self.InternalState() if not state else state
        self.pdf_data = self.PdfData() if not pdf_data else pdf_data
        self.heuristics: CommonCriteriaCert.Heuristics = self.Heuristics() if not heuristics else heuristics

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
        if res and len(res) == 1:
            return res[0]
        if res and len(res) > 1:
            raise ValueError(f"Expected single EAL in security_level field, got: {res}")
        else:
            if self.protection_profiles:
                return helpers.choose_lowest_eal({x.pp_eal for x in self.protection_profiles if x.pp_eal})
            else:
                return None

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
            self.cert_link,
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
            [x.pp_name for x in self.protection_profiles] if self.protection_profiles else np.nan,
            self.heuristics.cert_lab[0] if (self.heuristics.cert_lab and self.heuristics.cert_lab[0]) else np.nan,
        )

    def __str__(self) -> str:
        printed_manufacturer = self.manufacturer if self.manufacturer else "Unknown manufacturer"
        return str(printed_manufacturer) + " " + str(self.name) + " dgst: " + self.dgst

    def merge(self, other: CommonCriteriaCert, other_source: Optional[str] = None) -> None:
        """
        Merges with other CC sample. Assuming they come from different sources, e.g., csv and html.
        Assuming that html source has better protection profiles, they overwrite CSV info
        On other values the sanity checks are made.
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

    def get_keywords_df_row(self) -> dict[str, float]:
        """
        Returns dictionary of sums of matches of keywords in ST. Iterates over all categories
        """
        return dict(
            ChainMap(
                *[
                    sec_certs.utils.extract.get_sums_for_rules_subset(self.pdf_data.st_keywords, cat)
                    for cat in PANDAS_KEYWORDS_CATEGORIES
                ]
            )
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
                    ProtectionProfile(
                        pp_name=str(link.contents[0]), pp_eal=None, pp_link=CommonCriteriaCert.cc_url + link.get("href")
                    )
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
            cert.state.report_download_ok = True
            cert.state.report_pdf_hash = helpers.get_sha256_filepath(cert.state.report_pdf_path)
            cert.pdf_data.report_filename = unquote_plus(str(urlparse(cert.report_link).path).split("/")[-1])
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
            error_msg = f"failed to download ST from {cert.st_link}, code: {exit_code}"
            logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
            cert.state.st_download_ok = False
            cert.state.errors.append(error_msg)
        else:
            cert.state.st_download_ok = True
            cert.state.st_pdf_hash = helpers.get_sha256_filepath(cert.state.st_pdf_path)
            cert.pdf_data.st_filename = unquote_plus(str(urlparse(cert.st_link).path).split("/")[-1])
        return cert

    @staticmethod
    def convert_report_pdf(cert: CommonCriteriaCert) -> CommonCriteriaCert:
        """
        Converts the pdf certification report to txt, given the certificate. Staticmethod to allow for parallelization.

        :param CommonCriteriaCert cert: cert to download the pdf report for
        :return CommonCriteriaCert: the modified certificate with updated state
        """
        ocr_done, ok_result = sec_certs.utils.pdf.convert_pdf_file(
            cert.state.report_pdf_path, cert.state.report_txt_path
        )
        # If OCR was done the result was garbage
        cert.state.report_convert_garbage = ocr_done
        # And put the whole result into convert_ok
        cert.state.report_convert_ok = ok_result
        if not ok_result:
            error_msg = "failed to convert report pdf->txt"
            logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
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
        ocr_done, ok_result = sec_certs.utils.pdf.convert_pdf_file(cert.state.st_pdf_path, cert.state.st_txt_path)
        # If OCR was done the result was garbage
        cert.state.st_convert_garbage = ocr_done
        # And put the whole result into convert_ok
        cert.state.st_convert_ok = ok_result
        if not ok_result:
            error_msg = "failed to convert security target pdf->txt"
            logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
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
        response, cert.pdf_data.st_metadata = sec_certs.utils.pdf.extract_pdf_metadata(cert.state.st_pdf_path)
        if response != constants.RETURNCODE_OK:
            cert.state.st_extract_ok = False
            cert.state.errors.append(response)
        else:
            cert.state.st_extract_ok = True
        return cert

    @staticmethod
    def extract_report_pdf_metadata(cert: CommonCriteriaCert) -> CommonCriteriaCert:
        """
        Extracts metadata from certification report pdf given the certificate. Staticmethod to allow for parallelization.

        :param CommonCriteriaCert cert: cert to extract the metadata for.
        :return CommonCriteriaCert: the modified certificate with updated state
        """
        response, cert.pdf_data.report_metadata = sec_certs.utils.pdf.extract_pdf_metadata(cert.state.report_pdf_path)
        if response != constants.RETURNCODE_OK:
            cert.state.report_extract_ok = False
            cert.state.errors.append(response)
        else:
            cert.state.report_extract_ok = True
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
        report_keywords = sec_certs.utils.extract.extract_keywords(cert.state.report_txt_path, cc_rules)
        if report_keywords is None:
            cert.state.report_extract_ok = False
        else:
            cert.pdf_data.report_keywords = report_keywords
        return cert

    @staticmethod
    def extract_st_pdf_keywords(cert: CommonCriteriaCert) -> CommonCriteriaCert:
        """
        Matches regular expresions in txt obtained from security target and extracts the matches into attribute.
        Static method to allow for parallelization

        :param CommonCriteriaCert cert: certificate to extract the keywords for.
        :return CommonCriteriaCert: the modified certificate with extracted keywords.
        """
        st_keywords = sec_certs.utils.extract.extract_keywords(cert.state.st_txt_path, cc_rules)
        if st_keywords is None:
            cert.state.st_extract_ok = False
        else:
            cert.pdf_data.st_keywords = st_keywords
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

    def compute_heuristics_cert_id(self):
        """
        Compute the heuristics cert_id of this cert, using several methods.

        The candidate cert_ids are extracted from the frontpage, PDF metadata, filename, and keywords matches.

        Finally, the cert_id is canonicalized.
        """
        if not self.pdf_data:
            logger.warning("Cannot compute sample id when pdf files were not processed.")
            return
        # Extract candidate cert_ids
        candidates = self.pdf_data.candidate_cert_ids(self.scheme)

        if candidates:
            max_weight = max(candidates.values())
            max_candidates = list(filter(lambda x: candidates[x] == max_weight, candidates.keys()))
            max_candidates.sort(key=len, reverse=True)
            self.heuristics.cert_id = max_candidates[0]
