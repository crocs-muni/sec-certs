from __future__ import annotations

import copy
import re
from bisect import insort
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, ClassVar, Literal
from urllib.parse import unquote_plus, urlparse

import numpy as np
import requests
from bs4 import Tag

from sec_certs import constants
from sec_certs.cert_rules import SARS_IMPLIED_FROM_EAL, rules
from sec_certs.configuration import config
from sec_certs.converter import PDFConverter
from sec_certs.sample.cc_certificate_id import CertificateId, canonicalize, schemes
from sec_certs.sample.certificate import Certificate, References, logger
from sec_certs.sample.certificate import Heuristics as BaseHeuristics
from sec_certs.sample.certificate import PdfData as BasePdfData
from sec_certs.sample.document_state import DocumentState
from sec_certs.sample.sar import SAR
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.serialization.pandas import PandasSerializableType
from sec_certs.utils import helpers, sanitization
from sec_certs.utils.extract import normalize_match_string


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
    class InternalState(ComplexSerializableType):
        """
        Holds internal state of the certificate, whether downloads and converts of individual components succeeded. Also
        holds information about errors and paths to the files.
        """

        report: DocumentState = field(default_factory=DocumentState)
        st: DocumentState = field(default_factory=DocumentState)
        cert: DocumentState = field(default_factory=DocumentState)

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
        prev_certificates: list[str] | None = field(default=None)
        next_certificates: list[str] | None = field(default=None)
        st_references: References = field(default_factory=References)
        report_references: References = field(default_factory=References)
        # Contains direct outward references merged from both st, and report sources, annotated with ReferenceAnnotator
        # TODO: Reference meanings as Enum if we work with it further.
        annotated_references: dict[str, str] | None = field(default=None)
        extracted_sars: set[SAR] | None = field(default=None)
        direct_transitive_cves: set[str] | None = field(default=None)
        indirect_transitive_cves: set[str] | None = field(default=None)
        scheme_data: dict[str, Any] | None = field(default=None)
        protection_profiles: set[str] | None = field(default=None)
        eal: str | None = field(default=None)

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
        "protection_profile_links",
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
        protection_profile_links: set[str] | None,
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
        self.protection_profile_links = protection_profile_links
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
    def actual_sars(self) -> set[SAR] | None:
        """
        Computes actual SARs. First, SARs implied by EAL are computed. Then, these are augmented with heuristically extracted SARs.

        :return Optional[Set[SAR]]: Set of actual SARs of a certificate, None if empty
        """
        sars = {}
        if self.heuristics.eal:
            sars = {x[0]: SAR(x[0], x[1]) for x in SARS_IMPLIED_FROM_EAL[self.heuristics.eal[:4]]}

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
            self.heuristics.eal,
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
            self.protection_profile_links if self.protection_profile_links else np.nan,
            self.heuristics.protection_profiles if self.heuristics.protection_profiles else np.nan,
            self.heuristics.cert_lab[0] if (self.heuristics.cert_lab and self.heuristics.cert_lab[0]) else np.nan,
        )

    def __str__(self) -> str:
        printed_manufacturer = self.manufacturer if self.manufacturer else "Unknown manufacturer"
        return str(printed_manufacturer) + " " + str(self.name) + " dgst: " + self.dgst

    def merge(self, other: CCCertificate, other_source: str | None = None) -> None:
        """
        Merges with other CC sample. Assuming they come from different sources, e.g., csv and html.
        Assuming that html source has better protection profiles, they overwrite CSV info.
        On other values the sanity checks are made.
        """
        if self != other:
            logger.warning(
                f"Attempting to merge divergent certificates: self[dgst]={self.dgst}, other[dgst]={other.dgst}"
            )

        # Prefer some values from the HTML
        # Links in CSV are currently (13.08.2024) broken.
        html_preferred_attrs = {
            "protection_profile_links",
            "maintenance_updates",
            "cert_link",
            "report_link",
            "st_link",
        }

        for att, val in vars(self).items():
            if (not val) or (other_source == "html" and att in html_preferred_attrs) or (att == "state"):
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
        if dct["protection_profile_links"]:
            new_dct["protection_profile_links"] = set(dct["protection_profile_links"])
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
    def _html_row_get_protection_profile_links(cell: Tag) -> set:
        protection_profile_links = set()
        for link in list(cell.find_all("a")):
            if link.get("href") is not None and "/ppfiles/" in link.get("href"):
                protection_profile_links.add(constants.CC_PORTAL_BASE_URL + link.get("href"))
        return protection_profile_links

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
                report_link = constants.CC_PORTAL_BASE_URL + link.get("href")
            elif title.startswith("Security Target"):
                security_target_link = constants.CC_PORTAL_BASE_URL + link.get("href")

        return report_link, security_target_link

    @staticmethod
    def _html_row_get_cert_link(cell: Tag) -> str | None:
        links = cell.find_all("a")
        return constants.CC_PORTAL_BASE_URL + links[0].get("href") if links else None

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
                    main_report_link = constants.CC_PORTAL_BASE_URL + link.get("href")
                elif link.get("title").startswith("Maintenance ST"):
                    main_st_link = constants.CC_PORTAL_BASE_URL + link.get("href")
                else:
                    logger.error("Unknown link in Maintenance part!")
            maintenance_updates.add(
                CCCertificate.MaintenanceReport(main_date, main_title, main_report_link, main_st_link)
            )
        return maintenance_updates

    @classmethod
    def from_html_row(cls, row: Tag, status: str, category: str) -> CCCertificate:
        """
        Creates a CC sample from html row of commoncriteriaportal.org webpage.
        """

        cells = list(row.find_all("td"))
        if len(cells) != 7:
            raise ValueError(f"Unexpected number of <td> elements in CC html row. Expected: 7, actual: {len(cells)}")

        name = CCCertificate._html_row_get_name(cells[0])
        manufacturer = CCCertificate._html_row_get_manufacturer(cells[1])
        manufacturer_web = CCCertificate._html_row_get_manufacturer_web(cells[1])
        scheme = CCCertificate._html_row_get_scheme(cells[6])
        security_level = CCCertificate._html_row_get_security_level(cells[5])
        protection_profile_links = CCCertificate._html_row_get_protection_profile_links(cells[0])
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
            protection_profile_links,
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
        report_json_dir: str | Path | None,
        st_json_dir: str | Path | None,
        cert_json_dir: str | Path | None,
    ) -> None:
        """
        Sets paths to files given the requested directories

        :param Optional[Union[str, Path]] report_pdf_dir: Directory where pdf reports shall be stored
        :param Optional[Union[str, Path]] st_pdf_dir: Directory where pdf security targets shall be stored
        :param Optional[Union[str, Path]] cert_pdf_dir: Directory where pdf certificates shall be stored
        :param Optional[Union[str, Path]] report_txt_dir: Directory where txt reports shall be stored
        :param Optional[Union[str, Path]] st_txt_dir: Directory where txt security targets shall be stored
        :param Optional[Union[str, Path]] cert_txt_dir: Directory where txt certificates shall be stored
        :param Optional[Union[str, Path]] report_json_dir: Directory where json reports shall be stored
        :param Optional[Union[str, Path]] st_json_dir: Directory where json security targets shall be stored
        :param Optional[Union[str, Path]] cert_json_dir: Directory where json certificates shall be stored
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

        if report_json_dir:
            self.state.report.json_path = Path(report_json_dir) / (self.dgst + ".json")
        if st_json_dir:
            self.state.st.json_path = Path(st_json_dir) / (self.dgst + ".json")
        if cert_json_dir:
            self.state.cert.json_path = Path(cert_json_dir) / (self.dgst + ".json")

    @staticmethod
    def _download_pdf(cert: CCCertificate, doc_type: Literal["report", "st", "cert"]):
        link = getattr(cert, f"{doc_type}_link")
        doc_state = getattr(cert.state, doc_type)
        exit_code = helpers.download_file(link, doc_state.pdf_path, proxy=config.cc_use_proxy) if link else "No link"

        if exit_code != requests.codes.ok:
            error_msg = f"failed to download {doc_type} from {link}, code: {exit_code}"
            logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
            doc_state.download_ok = False
        else:
            doc_state.download_ok = True
            doc_state.pdf_hash = helpers.get_sha256_filepath(doc_state.pdf_path)
            setattr(cert.pdf_data, f"{doc_type}_filename", unquote_plus(str(urlparse(link).path).split("/")[-1]))
        return cert

    @staticmethod
    def download_pdf_report(cert: CCCertificate) -> CCCertificate:
        """
        Downloads pdf of certification report given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to download the pdf report for
        :return CCCertificate: returns the modified certificate with updated state
        """
        return CCCertificate._download_pdf(cert, "report")

    @staticmethod
    def download_pdf_st(cert: CCCertificate) -> CCCertificate:
        """
        Downloads pdf of security target given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to download the pdf security target for
        :return CCCertificate: returns the modified certificate with updated state
        """
        return CCCertificate._download_pdf(cert, "st")

    @staticmethod
    def download_pdf_cert(cert: CCCertificate) -> CCCertificate:
        """
        Downloads pdf of the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to download the pdf of
        :return CCCertificate: returns the modified certificate with updated state
        """
        return CCCertificate._download_pdf(cert, "cert")

    @staticmethod
    def _convert_pdf(
        cert: CCCertificate, doc_type: Literal["report", "st", "cert"], converter: PDFConverter
    ) -> CCCertificate:
        doc_state = getattr(cert.state, doc_type)
        ok_result = converter.convert(doc_state.pdf_path, doc_state.txt_path, doc_state.json_path)
        doc_state.convert_ok = ok_result
        if not ok_result:
            error_msg = f"failed to convert {doc_type} pdf->txt"
            logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
        else:
            doc_state.txt_hash = helpers.get_sha256_filepath(doc_state.txt_path)
            if doc_state.json_path.exists():
                doc_state.json_hash = helpers.get_sha256_filepath(doc_state.json_path)
            else:
                doc_state.json_hash = None
        return cert

    @staticmethod
    def convert_report_pdf(cert: CCCertificate, converter: PDFConverter) -> CCCertificate:
        """
        Converts the pdf certification report to txt, given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to convert the pdf report for
        :return CCCertificate: the modified certificate with updated state
        """
        return CCCertificate._convert_pdf(cert, "report", converter)

    @staticmethod
    def convert_st_pdf(cert: CCCertificate, converter: PDFConverter) -> CCCertificate:
        """
        Converts the pdf security target to txt, given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to convert the pdf security target for
        :return CCCertificate: the modified certificate with updated state
        """
        return CCCertificate._convert_pdf(cert, "st", converter)

    @staticmethod
    def convert_cert_pdf(cert: CCCertificate, converter: PDFConverter) -> CCCertificate:
        """
        Converts the pdf certificate to txt, given the certificate. Staticmethod to allow for parallelization.

        :param CCCertificate cert: cert to convert the certificate for
        :return CCCertificate: the modified certificate with updated state
        """
        return CCCertificate._convert_pdf(cert, "cert", converter)

    def compute_heuristics_cert_versions(self, cert_ids: dict[str, CertificateId | None]) -> None:  # noqa: C901
        """
        Fills in the previous and next certificate versions based on the cert ID.
        """
        self.heuristics.prev_certificates = []
        self.heuristics.next_certificates = []
        own = cert_ids[self.dgst]
        if own is None:
            return
        if self.scheme not in ("DE", "FR", "ES", "NL", "MY"):
            # There is no version in the cert_id, so skip it
            return
        version = own.meta.get("version")
        for other_dgst, other in cert_ids.items():
            if other_dgst == self.dgst:
                # Skip ourselves
                continue
            if other is None or other.scheme != own.scheme:
                # The other does not have cert ID or is different scheme or does not have a version.
                continue
            other_version = other.meta.get("version")
            # Go over the own meta and compare, if some field other than version is different, bail out.
            # If all except the version are the same, we have a match.
            for key, value in own.meta.items():
                if key == "version":
                    continue
                if self.scheme == "DE" and key == "year":
                    # For German certs we want to also ignore the year in comparison.
                    continue
                if value != other.meta.get(key):
                    break
            else:
                if other_version is None and version is None:
                    # This means a duplicate ID is present, and it has no version.
                    # Just pass silently.
                    pass
                elif version is None:
                    insort(self.heuristics.next_certificates, str(other))
                elif other_version is None:
                    insort(self.heuristics.prev_certificates, str(other))
                else:
                    if other_version < version:
                        insort(self.heuristics.prev_certificates, str(other))
                    else:
                        insort(self.heuristics.next_certificates, str(other))

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
