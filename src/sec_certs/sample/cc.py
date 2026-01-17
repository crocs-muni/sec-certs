from __future__ import annotations

from bisect import insort
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

from bs4 import Tag

from sec_certs import constants
from sec_certs.sample.cc_certificate_id import CertificateId
from sec_certs.sample.cc_eucc_mixin import CC_EUCC_SampleMixin
from sec_certs.sample.certificate import Certificate, logger
from sec_certs.sample.heuristics import Heuristics
from sec_certs.sample.internal_state import InternalState
from sec_certs.sample.pdf_data import PdfData
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.serialization.pandas import PandasSerializableType
from sec_certs.utils import helpers, sanitization


class CCCertificate(
    CC_EUCC_SampleMixin,
    Certificate["CCCertificate", "Heuristics", "PdfData"],
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
        maintenance_updates: set[CCCertificate.MaintenanceReport] | None,
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
        self.state = state if state else InternalState()
        self.pdf_data = pdf_data if pdf_data else PdfData()
        self.heuristics = heuristics if heuristics else Heuristics()

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
