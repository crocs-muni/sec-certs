from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import unquote_plus, urlparse

import requests
from bs4 import Tag

import sec_certs.utils.extract
import sec_certs.utils.pdf
from sec_certs import constants
from sec_certs.cert_rules import cc_rules
from sec_certs.configuration import config
from sec_certs.sample.certificate import Certificate, logger
from sec_certs.sample.certificate import Heuristics as BaseHeuristics
from sec_certs.sample.certificate import PdfData as BasePdfData
from sec_certs.sample.document_state import DocumentState
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils import helpers, sanitization


class ProtectionProfile(
    Certificate["ProtectionProfile", "ProtectionProfile.Heuristics", "ProtectionProfile.PdfData"],
    ComplexSerializableType,
):
    @dataclass
    class Heuristics(BaseHeuristics, ComplexSerializableType):
        pass

    @dataclass
    class PdfData(BasePdfData, ComplexSerializableType):
        report_metadata: dict[str, Any] | None = field(default=None)
        pp_metadata: dict[str, Any] | None = field(default=None)
        report_keywords: dict[str, Any] | None = field(default=None)
        pp_keywords: dict[str, Any] | None = field(default=None)
        report_filename: str | None = field(default=None)
        pp_filename: str | None = field(default=None)

        def __bool__(self) -> bool:
            return any(x is not None for x in vars(self))

    @dataclass(eq=True)
    class WebData(ComplexSerializableType):
        category: str
        status: Literal["active", "archived"]
        is_collaborative: bool
        name: str
        version: str
        security_level: set[str]
        not_valid_before: date | None
        not_valid_after: date | None
        report_link: str | None
        pp_link: str | None
        scheme: str | None
        maintenances: list[tuple[date, str, str]]

        @property
        def eal(self) -> str | None:
            return helpers.choose_lowest_eal(self.security_level)

        @classmethod
        def from_html_row(
            cls, row: Tag, status: Literal["active", "archived"], category: str, is_collaborative: bool
        ) -> ProtectionProfile.WebData:
            if is_collaborative:
                return cls._from_html_row_collaborative(row, category)
            return cls._from_html_row_classic_pp(row, status, category)

        @classmethod
        def _from_html_row_classic_pp(
            cls, row: Tag, status: Literal["active", "archived"], category: str
        ) -> ProtectionProfile.WebData:
            cells = list(row.find_all("td"))
            if status == "active" and len(cells) != 6:
                raise ValueError(
                    f"Unexpected number of <td> elements in PP html row. Expected: 6, actual: {len(cells)}"
                )
            if status == "archived" and len(cells) != 7:
                raise ValueError(
                    f"Unexpected number of <td> elements in PP html row. Expected: 6, actual: {len(cells)}"
                )

            pp_link = cls._html_row_get_link(cells[0])
            pp_name = cls._html_row_get_name(cells[0])
            if not sanitization.sanitize_cc_link(pp_link):
                raise ValueError(f"pp_link for PP {pp_name} is empty, cannot create PP record")

            # TODO: Parse maintenance div here. See CC parsing.
            return cls(
                category,
                status,
                False,
                pp_name,
                cls._html_row_get_version(cells[1]),
                cls._html_row_get_security_level(cells[2]),
                cls._html_row_get_date(cells[3]),
                None if status == "active" else cls._html_row_get_date(cells[4]),
                cls._html_row_get_link(cells[-1]),
                pp_link,
                cls._html_row_get_scheme(cells[-2]),
                [],
            )

        @classmethod
        def _from_html_row_collaborative(cls, row: Tag, category: str) -> ProtectionProfile.WebData:
            cells = list(row.find_all("td"))
            if len(cells) != 5:
                raise ValueError(
                    f"Unexpected number of <td> elements in collaborative PP html row. Expected: 5, actual: {len(cells)}"
                )

            pp_link = cls._html_row_get_collaborative_pp_link(cells[0])
            pp_name = cls._html_row_get_collaborative_name(cells[0])
            if not sanitization.sanitize_cc_link(pp_link):
                raise ValueError(f"pp_link for PP {pp_name} is empty, cannot create PP record")

            return cls(
                category,
                "active",
                True,
                pp_name,
                cls._html_row_get_version(cells[1]),
                cls._html_row_get_security_level(cells[2]),
                cls._html_row_get_date(cells[3]),
                None,
                cls._html_row_get_link(cells[-1]),
                pp_link,
                None,
                [],
            )

        @staticmethod
        def _html_row_get_date(cell: Tag) -> date | None:
            text = cell.get_text()
            extracted_date = datetime.strptime(text, "%Y-%m-%d").date() if text else None
            return extracted_date

        @staticmethod
        def _html_row_get_name(cell: Tag) -> str:
            return cell.find_all("a")[0].string

        @staticmethod
        def _html_row_get_link(cell: Tag) -> str:
            return constants.CC_PORTAL_BASE_URL + cell.find_all("a")[0].get("href")

        @staticmethod
        def _html_row_get_version(cell: Tag) -> str:
            return cell.text

        @staticmethod
        def _html_row_get_security_level(cell: Tag) -> set[str]:
            return set(cell.stripped_strings)

        @staticmethod
        def _html_row_get_scheme(cell: Tag) -> str | None:
            schemes = list(cell.stripped_strings)
            return schemes[0] if schemes else None

        @staticmethod
        def _html_row_get_collaborative_name(cell: Tag) -> str:
            return list(cell.stripped_strings)[0]

        @staticmethod
        def _html_row_get_collaborative_pp_link(cell: Tag) -> str:
            return constants.CC_PORTAL_BASE_URL + [x for x in cell.find_all("a") if x.string == "Protection Profile"][
                0
            ].get("href")

    @dataclass
    class InternalState(ComplexSerializableType):
        pp: DocumentState = field(default_factory=DocumentState)
        report: DocumentState = field(default_factory=DocumentState)

    def __init__(
        self,
        web_data: WebData,
        pdf_data: PdfData | None = None,
        heuristics: Heuristics | None = None,
        state: InternalState | None = None,
    ):
        super().__init__()
        self.web_data: ProtectionProfile.WebData = web_data
        self.pdf_data: ProtectionProfile.PdfData = pdf_data if pdf_data else ProtectionProfile.PdfData()
        self.heuristics: ProtectionProfile.Heuristics = heuristics if heuristics else ProtectionProfile.Heuristics()
        self.state: ProtectionProfile.InternalState = state if state else ProtectionProfile.InternalState()

    @property
    def dgst(self) -> str:
        return helpers.get_first_16_bytes_sha256(
            "|".join([self.web_data.category, self.web_data.name, self.web_data.version])
        )

    @property
    def label_studio_title(self) -> str:
        return self.web_data.name

    def merge(self, other: ProtectionProfile, other_source: str | None = None) -> None:
        raise ValueError("Merging of PPs not implemented.")

    def set_local_paths(
        self,
        report_pdf_dir: str | Path | None,
        pp_pdf_dir: str | Path | None,
        report_txt_dir: str | Path | None,
        pp_txt_dir: str | Path | None,
    ) -> None:
        if report_pdf_dir:
            self.state.report.pdf_path = Path(report_pdf_dir) / f"{self.dgst}.pdf"
        if pp_pdf_dir:
            self.state.pp.pdf_path = Path(pp_pdf_dir) / f"{self.dgst}.pdf"
        if report_txt_dir:
            self.state.report.txt_path = Path(report_txt_dir) / f"{self.dgst}.txt"
        if pp_txt_dir:
            self.state.pp.txt_path = Path(pp_txt_dir) / f"{self.dgst}.txt"

    @classmethod
    def from_html_row(
        cls, row: Tag, status: Literal["active", "archived"], category: str, is_collaborative: bool
    ) -> ProtectionProfile:
        return cls(ProtectionProfile.WebData.from_html_row(row, status, category, is_collaborative))

    @staticmethod
    def download_pdf_report(cert: ProtectionProfile) -> ProtectionProfile:
        exit_code: str | int
        if not cert.web_data.report_link:
            exit_code = "No link"
        else:
            exit_code = helpers.download_file(
                cert.web_data.report_link, cert.state.report.pdf_path, proxy=config.cc_use_proxy
            )
        if exit_code != requests.codes.ok:
            error_msg = f"failed to download report from {cert.web_data.report_link}, code: {exit_code}"
            logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
            cert.state.report.download_ok = False
        else:
            cert.state.report.download_ok = True
            cert.state.report.pdf_hash = helpers.get_sha256_filepath(cert.state.report.pdf_path)
            cert.pdf_data.report_filename = unquote_plus(str(urlparse(cert.web_data.report_link).path).split("/")[-1])
        return cert

    @staticmethod
    def download_pdf_pp(cert: ProtectionProfile) -> ProtectionProfile:
        exit_code: str | int
        if not cert.web_data.pp_link:
            exit_code = "No link"
        else:
            exit_code = helpers.download_file(cert.web_data.pp_link, cert.state.pp.pdf_path, proxy=config.cc_use_proxy)
        if exit_code != requests.codes.ok:
            error_msg = f"failed to download PP from {cert.web_data.pp_link}, code: {exit_code}"
            logger.error(f"Cert dgst: {cert.dgst} " + error_msg)
            cert.state.pp.download_ok = False
        else:
            cert.state.pp.download_ok = True
            cert.state.pp.pdf_hash = helpers.get_sha256_filepath(cert.state.pp.pdf_path)
            cert.pdf_data.pp_filename = unquote_plus(str(urlparse(cert.web_data.pp_link).path).split("/")[-1])
        return cert

    @staticmethod
    def convert_report_pdf(cert: ProtectionProfile) -> ProtectionProfile:
        ocr_done, ok_result = sec_certs.utils.pdf.convert_pdf_file(
            cert.state.report.pdf_path, cert.state.report.txt_path
        )
        cert.state.report.convert_garbage = ocr_done
        cert.state.report.convert_ok = ok_result
        if not ok_result:
            logger.error(f"Cert dgst: {cert.dgst} failed to convert report pdf to txt")
        else:
            cert.state.report.txt_hash = helpers.get_sha256_filepath(cert.state.report.txt_path)
        return cert

    @staticmethod
    def convert_pp_pdf(cert: ProtectionProfile) -> ProtectionProfile:
        ocr_done, ok_result = sec_certs.utils.pdf.convert_pdf_file(cert.state.pp.pdf_path, cert.state.pp.txt_path)
        cert.state.pp.convert_garbage = ocr_done
        cert.state.pp.convert_ok = ok_result
        if not ok_result:
            logger.error(f"Cert dgst: {cert.dgst} failed to convert PP pdf to txt")
        else:
            cert.state.pp.txt_hash = helpers.get_sha256_filepath(cert.state.pp.txt_path)
        return cert

    @staticmethod
    def extract_report_pdf_metadata(cert: ProtectionProfile) -> ProtectionProfile:
        response, cert.pdf_data.report_metadata = sec_certs.utils.pdf.extract_pdf_metadata(cert.state.report.pdf_path)
        cert.state.report.extract_ok = response == constants.RETURNCODE_OK
        return cert

    @staticmethod
    def extract_pp_pdf_metadata(cert: ProtectionProfile) -> ProtectionProfile:
        response, cert.pdf_data.pp_metadata = sec_certs.utils.pdf.extract_pdf_metadata(cert.state.pp.pdf_path)
        cert.state.pp.extract_ok = response == constants.RETURNCODE_OK
        return cert

    @staticmethod
    def extract_report_pdf_keywords(cert: ProtectionProfile) -> ProtectionProfile:
        report_keywords = sec_certs.utils.extract.extract_keywords(cert.state.report.txt_path, cc_rules)
        if report_keywords is None:
            cert.state.report.extract_ok = False
        else:
            cert.pdf_data.report_keywords = report_keywords
        return cert

    @staticmethod
    def extract_pp_pdf_keywords(cert: ProtectionProfile) -> ProtectionProfile:
        pp_keywords = sec_certs.utils.extract.extract_keywords(cert.state.pp.txt_path, cc_rules)
        if pp_keywords is None:
            cert.state.pp.extract_ok = False
        else:
            cert.pdf_data.pp_keywords = pp_keywords
        return cert
