from __future__ import annotations

import copy
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import unquote_plus, urlparse

import numpy as np
import requests
from bs4 import Tag

import sec_certs.utils.extract
import sec_certs.utils.pdf
from sec_certs import constants
from sec_certs.cert_rules import SARS_IMPLIED_FROM_EAL, cc_rules, rules, security_level_csv_scan
from sec_certs.configuration import config
from sec_certs.sample.cc_certificate_id import canonicalize, schemes
from sec_certs.sample.certificate import Certificate, References, logger
from sec_certs.sample.certificate import Heuristics as BaseHeuristics
from sec_certs.sample.certificate import PdfData as BasePdfData
from sec_certs.sample.protection_profile import ProtectionProfile
from sec_certs.sample.sar import SAR
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.serialization.pandas import PandasSerializableType
from sec_certs.utils import helpers, sanitization
from sec_certs.utils.extract import normalize_match_string, scheme_frontpage_functions


class CCCertificate(
    Certificate["CCCertificate", "CCCertificate.Heuristics", "CCCertificate.PdfData"],
    PandasSerializableType,
    ComplexSerializableType,
):
    """
    Data structure for common criteria certificate. Contains several inner classes that layer the data logic.
    Can be serialized into/from json (`ComplexSerializableType`) or pandas (`PandasSerializableType)`.
    Is basic element of `CCDataset`. The functionality is mostly related to holding data and transformations that
    the certificate can handle itself. `CCDataset` class then instrument this functionality.
    """

    cc_url = "https://www.commoncriteriaportal.org"

    @dataclass(eq=True, frozen=True)
    class MaintenanceReport(ComplexSerializableType):
        """
        Object for holding maintenance reports.
        """

        maintenance_date: date | None
        maintenance_title: str | None
        maintenance_report_link: str | None
        maintenance_st_link: str | None

        def __post_init__(self):
            super().__setattr__("maintenance_report_link", sanitization.sanitize_link(self.maintenance_report_link))
            super().__setattr__("maintenance_st_link", sanitization.sanitize_link(self.maintenance_st_link))
            super().__setattr__("maintenance_title", sanitization.sanitize_string(self.maintenance_title))
            super().__setattr__("maintenance_date", sanitization.sanitize_date(self.maintenance_date))

        @classmethod
        def from_dict(cls, dct: dict) -> CCCertificate.MaintenanceReport:
            new_dct = dct.copy()
            new_dct["maintenance_date"] = (
                date.fromisoformat(dct["maintenance_date"])
                if isinstance(dct["maintenance_date"], str)
                else dct["maintenance_date"]
            )
            return super().from_dict(new_dct)

        def __lt__(self, other):
            return self.maintenance_date < other.maintenance_date

    @dataclass
    class DocumentState(ComplexSerializableType):
        download_ok: bool = False  # Whether download went OK
        convert_garbage: bool = False  # Whether initial conversion resulted in garbage
        convert_ok: bool = False  # Whether overall conversion went OK (either pdftotext or via OCR)
        extract_ok: bool = False  # Whether extraction went OK

        pdf_hash: str | None = None
        txt_hash: str | None = None

        _pdf_path: Path | None = None
        _txt_path: Path | None = None

        def is_ok_to_download(self, fresh: bool = True) -> bool:
            return True if fresh else not self.download_ok

        def is_ok_to_convert(self, fresh: bool = True) -> bool:
            return self.download_ok if fresh else self.download_ok and not self.convert_ok

        def is_ok_to_analyze(self, fresh: bool = True) -> bool:
            if fresh:
                return self.download_ok and self.convert_ok
            else:
                return self.download_ok and self.convert_ok and not self.extract_ok

        @property
        def pdf_path(self) -> Path:
            if not self._pdf_path:
                raise ValueError(f"pdf_path not set on {type(self)}")
            return self._pdf_path

        @pdf_path.setter
        def pdf_path(self, pth: str | Path | None) -> None:
            self._pdf_path = Path(pth) if pth else None

        @property
        def txt_path(self) -> Path:
            if not self._txt_path:
                raise ValueError(f"txt_path not set on {type(self)}")
            return self._txt_path

        @txt_path.setter
        def txt_path(self, pth: str | Path | None) -> None:
            self._txt_path = Path(pth) if pth else None

        @property
        def serialized_attributes(self) -> list[str]:
            return [
                "download_ok",
                "convert_garbage",
                "convert_ok",
                "extract_ok",
                "pdf_hash",
                "txt_hash",
            ]

    @dataclass(init=False)
    class InternalState(ComplexSerializableType):
        """
        Holds internal state of the certificate, whether downloads and converts of individual components succeeded. Also
        holds information about errors and paths to the files.
        """

        report: CCCertificate.DocumentState
        st: CCCertificate.DocumentState
        cert: CCCertificate.DocumentState

        def __init__(
            self,
            report: CCCertificate.DocumentState | None = None,
            st: CCCertificate.DocumentState | None = None,
            cert: CCCertificate.DocumentState | None = None,
        ):
            super().__init__()
            self.report = report if report is not None else CCCertificate.DocumentState()
            self.st = st if st is not None else CCCertificate.DocumentState()
            self.cert = cert if cert is not None else CCCertificate.DocumentState()

        @property
        def serialized_attributes(self) -> list[str]:
            return ["report", "st", "cert"]

    @dataclass
    class PdfData(BasePdfData, ComplexSerializableType):
        """
        Class that holds data extracted from pdf files.
        """

        report_metadata: dict[str, Any] | None = field(default=None)
        st_metadata: dict[str, Any] | None = field(default=None)
        cert_metadata: dict[str, Any] | None = field(default=None)
        report_frontpage: dict[str, dict[str, Any]] | None = field(default=None)
        st_frontpage: dict[str, dict[str, Any]] | None = field(
            default=None
        )  # TODO: Unused, we have no frontpage matching for targets
        cert_frontpage: dict[str, dict[str, Any]] | None = field(
            default=None
        )  # TODO: Unused, we have no frontpage matching for certs
        report_keywords: dict[str, Any] | None = field(default=None)
        st_keywords: dict[str, Any] | None = field(default=None)
        cert_keywords: dict[str, Any] | None = field(default=None)
        report_filename: str | None = field(default=None)
        st_filename: str | None = field(default=None)
        cert_filename: str | None = field(default=None)

        def __bool__(self) -> bool:
            return any(x is not None for x in vars(self))

        @property
        def cert_lab(self) -> list[str] | None:
            """
            Returns labs for which certificate data was parsed.
            """
            if not self.report_frontpage:
                return None
            labs = [
                data["cert_lab"].split(" ")[0].upper()
                for scheme, data in self.report_frontpage.items()
                if data and "cert_lab" in data
            ]
            return labs if labs else None

        def frontpage_cert_id(self, scheme: str) -> dict[str, float]:
            """
            Get cert_id candidate from the frontpage of the report.
            """
            if not self.report_frontpage:
                return {}
            data = self.report_frontpage.get(scheme)
            if not data:
                return {}
            cert_id = data.get("cert_id")
            if not cert_id:
                return {}
            else:
                return {cert_id: 1.0}

        def filename_cert_id(self, scheme: str) -> dict[str, float]:
            """
            Get cert_id candidates from the matches in the report filename and cert filename.
            """
            scheme_filename_rules = rules["cc_filename_cert_id"][scheme]
            if not scheme_filename_rules:
                return {}
            scheme_meta = schemes[scheme]
            results: dict[str, float] = {}
            for fname in (self.report_filename, self.cert_filename):
                if not fname:
                    continue

                matches: Counter = Counter()
                for rule in scheme_filename_rules:
                    match = re.search(rule, fname)
                    if match:
                        try:
                            meta = match.groupdict()
                            cert_id = scheme_meta(meta)
                            matches[cert_id] += 1
                        except Exception:
                            continue
                if not matches:
                    continue
                total = max(matches.values())

                for candidate, count in matches.items():
                    results.setdefault(candidate, 0)
                    results[candidate] += count / total
            # TODO count length in weight
            return results

        def keywords_cert_id(self, scheme: str) -> dict[str, float]:
            """
            Get cert_id candidates from the keywords matches in the report and cert.
            """
            results: dict[str, float] = {}
            for keywords in (self.report_keywords, self.cert_keywords):
                if not keywords:
                    continue
                cert_id_matches = keywords.get("cc_cert_id")
                if not cert_id_matches:
                    continue

                if scheme not in cert_id_matches:
                    continue
                matches: Counter = Counter(cert_id_matches[scheme])
                if not matches:
                    continue
                total = max(matches.values())

                for candidate, count in matches.items():
                    results.setdefault(candidate, 0)
                    results[candidate] += count / total
            # TODO count length in weight
            return results

        def metadata_cert_id(self, scheme: str) -> dict[str, float]:
            """
            Get cert_id candidates from the report metadata.
            """
            scheme_rules = rules["cc_cert_id"][scheme]
            fields = ("/Title", "/Subject")
            results: dict[str, float] = {}
            for metadata in (self.report_metadata, self.cert_metadata):
                if not metadata:
                    continue
                matches: Counter = Counter()
                for meta_field in fields:
                    field_val = metadata.get(meta_field)
                    if not field_val:
                        continue
                    for rule in scheme_rules:
                        match = re.search(rule, field_val)
                        if match:
                            cert_id = normalize_match_string(match.group())
                            matches[cert_id] += 1
                if not matches:
                    continue
                total = max(matches.values())

                for candidate, count in matches.items():
                    results.setdefault(candidate, 0)
                    results[candidate] += count / total
            # TODO count length in weight
            return results

        def candidate_cert_ids(self, scheme: str) -> dict[str, float]:
            frontpage_id = self.frontpage_cert_id(scheme)
            metadata_id = self.metadata_cert_id(scheme)
            filename_id = self.filename_cert_id(scheme)
            keywords_id = self.keywords_cert_id(scheme)

            # Join them and weigh them, each is normalized with weights from 0 to 1 (if anything is returned)
            candidates: dict[str, float] = defaultdict(lambda: 0.0)
            # TODO: Add heuristic based on ordering of ids (and extracted year + increment)
            # TODO: Add heuristic based on length
            # TODO: Add heuristic based on id "richness", we want to prefer IDs that have more components.
            # If we cannot canonicalize, just skip that ID.
            for candidate, count in frontpage_id.items():
                try:
                    candidates[canonicalize(candidate, scheme)] += count * 1.5
                except Exception:
                    continue
            for candidate, count in metadata_id.items():
                try:
                    candidates[canonicalize(candidate, scheme)] += count * 1.2
                except Exception:
                    continue
            for candidate, count in keywords_id.items():
                try:
                    candidates[canonicalize(candidate, scheme)] += count * 1.0
                except Exception:
                    continue
            for candidate, count in filename_id.items():
                try:
                    candidates[canonicalize(candidate, scheme)] += count * 1.0
                except Exception:
                    continue
            return candidates

    @dataclass
    class Heuristics(BaseHeuristics, ComplexSerializableType):
        """
        Class for various heuristics related to CCCertificate
        """

        extracted_versions: set[str] | None = field(default=None)
        cpe_matches: set[str] | None = field(default=None)
        verified_cpe_matches: set[str] | None = field(default=None)
        related_cves: set[str] | None = field(default=None)
        cert_lab: list[str] | None = field(default=None)
        cert_id: str | None = field(default=None)
        st_references: References = field(default_factory=References)
        report_references: References = field(default_factory=References)

        # Contains direct outward references merged from both st, and report sources, annotated with ReferenceAnnotator
        # TODO: Reference meanings as Enum if we work with it further.
        annotated_references: dict[str, str] | None = field(default=None)
        extracted_sars: set[SAR] | None = field(default=None)
        direct_transitive_cves: set[str] | None = field(default=None)
        indirect_transitive_cves: set[str] | None = field(default=None)
        scheme_data: dict[str, Any] | None = field(default=None)

        @property
        def serialized_attributes(self) -> list[str]:
            return copy.deepcopy(super().serialized_attributes)

    pandas_columns: ClassVar[list[str]] = [
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
        manufacturer: str | None,
        scheme: str,
        security_level: str | set[str],
        not_valid_before: date | None,
        not_valid_after: date | None,
        report_link: str | None,
        st_link: str | None,
        cert_link: str | None,
        manufacturer_web: str | None,
        protection_profiles: set[ProtectionProfile] | None,
        maintenance_updates: set[MaintenanceReport] | None,
        state: InternalState | None,
        pdf_data: PdfData | None,
        heuristics: Heuristics | None,
    ):
        super().__init__()

        self.status = status
        self.category = category
        self.name = sanitization.sanitize_string(name)

        self.manufacturer = None
        if manufacturer:
            self.manufacturer = sanitization.sanitize_string(manufacturer)

        self.scheme = scheme
        self.security_level = sanitization.sanitize_security_levels(security_level)
        self.not_valid_before = sanitization.sanitize_date(not_valid_before)
        self.not_valid_after = sanitization.sanitize_date(not_valid_after)
        self.report_link = sanitization.sanitize_link(report_link)
        self.st_link = sanitization.sanitize_link(st_link)
        self.cert_link = sanitization.sanitize_link(cert_link)
        self.manufacturer_web = sanitization.sanitize_link(manufacturer_web)
        self.protection_profiles = protection_profiles
        self.maintenance_updates = maintenance_updates
        self.state = state if state else self.InternalState()
        self.pdf_data = pdf_data if pdf_data else self.PdfData()
        self.heuristics: CCCertificate.Heuristics = heuristics if heuristics else self.Heuristics()

    @property
    def dgst(self) -> str:
        """
        Computes the primary key of the sample using first 16 bytes of SHA-256 digest
        """
        if not (self.name is not None and self.category is not None):
            raise RuntimeError("Certificate digest can't be computed, because information is missing.")
        return helpers.get_first_16_bytes_sha256(
            "|".join(
                [
                    self.category,
                    self.name,
                    sanitization.sanitize_link_fname(self.report_link) or "None",
                    sanitization.sanitize_link_fname(self.st_link) or "None",
                ]
            )
        )

    @property
    def old_dgst(self) -> str:
        if not (self.name is not None and self.report_link is not None and self.category is not None):
            raise RuntimeError("Certificate digest can't be computed, because information is missing.")
        return helpers.get_first_16_bytes_sha256(
            self.category + self.name + sanitization.sanitize_cc_link(self.report_link)  # type: ignore
        )

    @property
    def older_dgst(self) -> str:
        if not (self.name is not None and self.report_link is not None and self.category is not None):
            raise RuntimeError("Certificate digest can't be computed, because information is missing.")
        return helpers.get_first_16_bytes_sha256(self.category + self.name + self.report_link)

    @property
    def eal(self) -> str | None:
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
    def actual_sars(self) -> set[SAR] | None:
        """
        Computes actual SARs. First, SARs implied by EAL are computed. Then, these are augmented with heuristically extracted SARs
        :return Optional[Set[SAR]]: Set of actual SARs of a certificate, None if empty
        """
        sars = {}
        if self.eal:
            sars = {x[0]: SAR(x[0], x[1]) for x in SARS_IMPLIED_FROM_EAL[self.eal[:4]]}

        if self.heuristics.extracted_sars:
            for sar in self.heuristics.extracted_sars:
                if sar not in sars or sar.level > sars[sar.family].level:
                    sars[sar.family] = sar

        return set(sars.values()) if sars else None

    @property
    def label_studio_title(self) -> str | None:
        return self.name

    @property
    def pandas_tuple(self) -> tuple:
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

    def merge(self, other: CCCertificate, other_source: str | None = None) -> None:
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
            if (
                (not val)
                or (other_source == "html" and att == "protection_profiles")
                or (other_source == "html" and att == "maintenance_updates")
                or (att == "state")
            ):
                setattr(self, att, getattr(other, att))
            else:
                if getattr(self, att) != getattr(other, att):
                    logger.warning(
                        f"When merging certificates with dgst {self.dgst}, the following mismatch occured: Attribute={att}, self[{att}]={getattr(self, att)}, other[{att}]={getattr(other, att)}"
                    )

    @classmethod
    def from_dict(cls, dct: dict) -> CCCertificate:
        """
        Deserializes dictionary into `CCCertificate`
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
        return super(cls, CCCertificate).from_dict(new_dct)

    @staticmethod
    def _html_row_get_name(cell: Tag) -> str:
        return list(cell.stripped_strings)[0]

    @staticmethod
    def _html_row_get_manufacturer(cell: Tag) -> str | None:
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
    def _html_row_get_manufacturer_web(cell: Tag) -> str | None:
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
                        pp_name=str(link.contents[0]), pp_eal=None, pp_link=CCCertificate.cc_url + link.get("href")
                    )
                )
        return protection_profiles

    @staticmethod
    def _html_row_get_date(cell: Tag) -> date | None:
        text = cell.get_text()
        extracted_date = datetime.strptime(text, "%Y-%m-%d").date() if text else None
        return extracted_date

    @staticmethod
    def _html_row_get_report_st_links(cell: Tag) -> tuple[str | None, str | None]:
        links = cell.find_all("a")

        report_link: str | None = None
        security_target_link: str | None = None
        for link in links:
            title = link.get("title")
            if not title:
                continue
            if title.startswith("Certification Report"):
                report_link = CCCertificate.cc_url + link.get("href")
            elif title.startswith("Security Target"):
                security_target_link = CCCertificate.cc_url + link.get("href")

        return report_link, security_target_link

    @staticmethod
    def _html_row_get_cert_link(cell: Tag) -> str | None:
        links = cell.find_all("a")
        return CCCertificate.cc_url + links[0].get("href") if links else None

    @staticmethod
    def _html_row_get_maintenance_div(cell: Tag) -> Tag | None:
        divs = cell.find_all("div")
        for d in divs:
            if d.find("div") and d.stripped_strings and list(d.stripped_strings)[0] == "Maintenance Report(s)":
                return d
        return None

    @staticmethod
    def _html_row_get_maintenance_updates(main_div: Tag) -> set[CCCertificate.MaintenanceReport]:
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
                    main_report_link = CCCertificate.cc_url + link.get("href")
                elif link.get("title").startswith("Maintenance ST"):
                    main_st_link = CCCertificate.cc_url + link.get("href")
                else:
                    logger.error("Unknown link in Maintenance part!")
            maintenance_updates.add(
                CCCertificate.MaintenanceReport(main_date, main_title, main_report_link, main_st_link)
            )
        return maintenance_updates

    @classmethod
    def from_html_row(cls, row: Tag, status: str, category: str) -> CCCertificate:
        """
        Creates a CC sample from html row of commoncriteria.org webpage.
        """

        cells = list(row.find_all("td"))
        if len(cells) != 7:
            raise ValueError(f"Unexpected number of <td> elements in CC html row. Expected: 7, actual: {len(cells)}")

        name = CCCertificate._html_row_get_name(cells[0])
        manufacturer = CCCertificate._html_row_get_manufacturer(cells[1])
        manufacturer_web = CCCertificate._html_row_get_manufacturer_web(cells[1])
        scheme = CCCertificate._html_row_get_scheme(cells[6])
        security_level = CCCertificate._html_row_get_security_level(cells[5])
        protection_profiles = CCCertificate._html_row_get_protection_profiles(cells[0])
        not_valid_before = CCCertificate._html_row_get_date(cells[3])
        not_valid_after = CCCertificate._html_row_get_date(cells[4])
        report_link, st_link = CCCertificate._html_row_get_report_st_links(cells[0])
        cert_link = CCCertificate._html_row_get_cert_link(cells[2])
        maintenance_div = CCCertificate._html_row_get_maintenance_div(cells[0])
        maintenances = CCCertificate._html_row_get_maintenance_updates(maintenance_div) if maintenance_div else set()

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
        report_pdf_dir: str | Path | None,
        st_pdf_dir: str | Path | None,
        cert_pdf_dir: str | Path | None,
        report_txt_dir: str | Path | None,
        st_txt_dir: str | Path | None,
        cert_txt_dir: str | Path | None,
    ) -> None:
        """
        Sets paths to files given the requested directories

        :param Optional[Union[str, Path]] report_pdf_dir: Directory where pdf reports shall be stored
        :param Optional[Union[str, Path]] st_pdf_dir: Directory where pdf security targets shall be stored
        :param Optional[Union[str, Path]] cert_pdf_dir: Directory where pdf certificates shall be stored
        :param Optional[Union[str, Path]] report_txt_dir: Directory where txt reports shall be stored
        :param Optional[Union[str, Path]] st_txt_dir: Directory where txt security targets shall be stored
        :param Optional[Union[str, Path]] cert_txt_dir: Directory where txtcertificates shall be stored
        """
        if report_pdf_dir:
            self.state.report.pdf_path = Path(report_pdf_dir) / (self.dgst + ".pdf")
        if st_pdf_dir:
            self.state.st.pdf_path = Path(st_pdf_dir) / (self.dgst + ".pdf")
        if cert_pdf_dir:
            self.state.cert.pdf_path = Path(cert_pdf_dir) / (self.dgst + ".pdf")
        if report_txt_dir:
            self.state.report.txt_path = Path(report_txt_dir) / (self.dgst + ".txt")
        if st_txt_dir:
            self.state.st.txt_path = Path(st_txt_dir) / (self.dgst + ".txt")
        if cert_txt_dir:
            self.state.cert.txt_path = Path(cert_txt_dir) / (self.dgst + ".txt")

    @staticmethod
    def download_pdf_report(cert: CCCertificate) -> CCCertificate:
        """
        Downloads pdf of certification report given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to download the pdf report for
        :return CCCertificate: returns the modified certificate with updated state
        """
        exit_code: str | int
        if not cert.report_link:
            exit_code = "No link"
        else:
            exit_code = helpers.download_file(cert.report_link, cert.state.report.pdf_path, proxy=config.cc_use_proxy)
        if exit_code != requests.codes.ok:
            error_msg = f"failed to download report from {cert.report_link}, code: {exit_code}"
            logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
            cert.state.report.download_ok = False
        else:
            cert.state.report.download_ok = True
            cert.state.report.pdf_hash = helpers.get_sha256_filepath(cert.state.report.pdf_path)
            cert.pdf_data.report_filename = unquote_plus(str(urlparse(cert.report_link).path).split("/")[-1])
        return cert

    @staticmethod
    def download_pdf_st(cert: CCCertificate) -> CCCertificate:
        """
        Downloads pdf of security target given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to download the pdf security target for
        :return CCCertificate: returns the modified certificate with updated state
        """
        exit_code: str | int = (
            helpers.download_file(cert.st_link, cert.state.st.pdf_path, proxy=config.cc_use_proxy)
            if cert.st_link
            else "No link"
        )

        if exit_code != requests.codes.ok:
            error_msg = f"failed to download ST from {cert.st_link}, code: {exit_code}"
            logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
            cert.state.st.download_ok = False
        else:
            cert.state.st.download_ok = True
            cert.state.st.pdf_hash = helpers.get_sha256_filepath(cert.state.st.pdf_path)
            cert.pdf_data.st_filename = unquote_plus(str(urlparse(cert.st_link).path).split("/")[-1])
        return cert

    @staticmethod
    def download_pdf_cert(cert: CCCertificate) -> CCCertificate:
        """
        Downloads pdf of the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to download the pdf of
        :return CCCertificate: returns the modified certificate with updated state
        """
        exit_code: str | int = (
            helpers.download_file(cert.cert_link, cert.state.cert.pdf_path, proxy=config.cc_use_proxy)
            if cert.cert_link
            else "No link"
        )

        if exit_code != requests.codes.ok:
            error_msg = f"failed to download certificate from {cert.cert_link}, code: {exit_code}"
            logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
            cert.state.cert.download_ok = False
        else:
            cert.state.cert.download_ok = True
            cert.state.cert.pdf_hash = helpers.get_sha256_filepath(cert.state.cert.pdf_path)
            cert.pdf_data.cert_filename = unquote_plus(str(urlparse(cert.cert_link).path).split("/")[-1])
        return cert

    @staticmethod
    def convert_report_pdf(cert: CCCertificate) -> CCCertificate:
        """
        Converts the pdf certification report to txt, given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to convert the pdf report for
        :return CCCertificate: the modified certificate with updated state
        """
        ocr_done, ok_result = sec_certs.utils.pdf.convert_pdf_file(
            cert.state.report.pdf_path, cert.state.report.txt_path
        )
        # If OCR was done the result was garbage
        cert.state.report.convert_garbage = ocr_done
        # And put the whole result into convert_ok
        cert.state.report.convert_ok = ok_result
        if not ok_result:
            error_msg = "failed to convert report pdf->txt"
            logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
        else:
            cert.state.report.txt_hash = helpers.get_sha256_filepath(cert.state.report.txt_path)
        return cert

    @staticmethod
    def convert_st_pdf(cert: CCCertificate) -> CCCertificate:
        """
        Converts the pdf security target to txt, given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to convert the pdf security target for
        :return CCCertificate: the modified certificate with updated state
        """
        ocr_done, ok_result = sec_certs.utils.pdf.convert_pdf_file(cert.state.st.pdf_path, cert.state.st.txt_path)
        # If OCR was done the result was garbage
        cert.state.st.convert_garbage = ocr_done
        # And put the whole result into convert_ok
        cert.state.st.convert_ok = ok_result
        if not ok_result:
            error_msg = "failed to convert security target pdf->txt"
            logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
        else:
            cert.state.st.txt_hash = helpers.get_sha256_filepath(cert.state.st.txt_path)
        return cert

    @staticmethod
    def convert_cert_pdf(cert: CCCertificate) -> CCCertificate:
        """
        Converts the pdf certificate to txt, given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to convert the certificate for
        :return CCCertificate: the modified certificate with updated state
        """
        ocr_done, ok_result = sec_certs.utils.pdf.convert_pdf_file(cert.state.cert.pdf_path, cert.state.cert.txt_path)
        # If OCR was done the result was garbage
        cert.state.cert.convert_garbage = ocr_done
        # And put the whole result into convert_ok
        cert.state.cert.convert_ok = ok_result
        if not ok_result:
            error_msg = "failed to convert security target pdf->txt"
            logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
        else:
            cert.state.cert.txt_hash = helpers.get_sha256_filepath(cert.state.cert.txt_path)
        return cert

    @staticmethod
    def extract_report_pdf_metadata(cert: CCCertificate) -> CCCertificate:
        """
        Extracts metadata from certification report pdf given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to extract the metadata for.
        :return CCCertificate: the modified certificate with updated state
        """
        response, cert.pdf_data.report_metadata = sec_certs.utils.pdf.extract_pdf_metadata(cert.state.report.pdf_path)
        if response != constants.RETURNCODE_OK:
            cert.state.report.extract_ok = False
        else:
            cert.state.report.extract_ok = True
        return cert

    @staticmethod
    def extract_st_pdf_metadata(cert: CCCertificate) -> CCCertificate:
        """
        Extracts metadata from security target pdf given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to extract the metadata for.
        :return CCCertificate: the modified certificate with updated state
        """
        response, cert.pdf_data.st_metadata = sec_certs.utils.pdf.extract_pdf_metadata(cert.state.st.pdf_path)
        if response != constants.RETURNCODE_OK:
            cert.state.st.extract_ok = False
        else:
            cert.state.st.extract_ok = True
        return cert

    @staticmethod
    def extract_cert_pdf_metadata(cert: CCCertificate) -> CCCertificate:
        """
        Extracts metadata from certificate pdf given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to extract the metadata for.
        :return CCCertificate: the modified certificate with updated state
        """
        response, cert.pdf_data.cert_metadata = sec_certs.utils.pdf.extract_pdf_metadata(cert.state.cert.pdf_path)
        if response != constants.RETURNCODE_OK:
            cert.state.cert.extract_ok = False
        else:
            cert.state.cert.extract_ok = True
        return cert

    @staticmethod
    def extract_report_pdf_frontpage(cert: CCCertificate) -> CCCertificate:
        """
        Extracts data from certification report pdf frontpage given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to extract the frontpage data for.
        :return CCCertificate: the modified certificate with updated state
        """
        cert.pdf_data.report_frontpage = {}

        if cert.scheme in scheme_frontpage_functions:
            header_func = scheme_frontpage_functions[cert.scheme]
            response, cert.pdf_data.report_frontpage[cert.scheme] = header_func(cert.state.report.txt_path)
            if response != constants.RETURNCODE_OK:
                cert.state.report.extract_ok = False
        return cert

    @staticmethod
    def extract_report_pdf_keywords(cert: CCCertificate) -> CCCertificate:
        """
        Matches regular expressions in txt obtained from certification report and extracts the matches into attribute.
        Static method to allow for parallelization

        :param CCCertificate cert: certificate to extract the keywords for.
        :return CCCertificate: the modified certificate with extracted keywords.
        """
        report_keywords = sec_certs.utils.extract.extract_keywords(cert.state.report.txt_path, cc_rules)
        if report_keywords is None:
            cert.state.report.extract_ok = False
        else:
            cert.pdf_data.report_keywords = report_keywords
        return cert

    @staticmethod
    def extract_st_pdf_keywords(cert: CCCertificate) -> CCCertificate:
        """
        Matches regular expressions in txt obtained from security target and extracts the matches into attribute.
        Static method to allow for parallelization

        :param CCCertificate cert: certificate to extract the keywords for.
        :return CCCertificate: the modified certificate with extracted keywords.
        """
        st_keywords = sec_certs.utils.extract.extract_keywords(cert.state.st.txt_path, cc_rules)
        if st_keywords is None:
            cert.state.st.extract_ok = False
        else:
            cert.pdf_data.st_keywords = st_keywords
        return cert

    @staticmethod
    def extract_cert_pdf_keywords(cert: CCCertificate) -> CCCertificate:
        """
        Matches regular expressions in txt obtained from the certificate and extracts the matches into attribute.
        Static method to allow for parallelization

        :param CCCertificate cert: certificate to extract the keywords for.
        :return CCCertificate: the modified certificate with extracted keywords.
        """
        cert_keywords = sec_certs.utils.extract.extract_keywords(cert.state.cert.txt_path, cc_rules)
        if cert_keywords is None:
            cert.state.cert.extract_ok = False
        else:
            cert.pdf_data.cert_keywords = cert_keywords
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
