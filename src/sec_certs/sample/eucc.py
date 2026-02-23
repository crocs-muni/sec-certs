from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml
from dateutil.relativedelta import relativedelta

from sec_certs.sample.cc_eucc_common import (
    Heuristics,
    InternalState,
    PdfData,
    actual_sars,
    compute_heuristics_cert_lab,
    dgst,
    set_local_paths,
)
from sec_certs.sample.certificate import Certificate
from sec_certs.sample.sar import SAR
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils import helpers, sanitization

with (Path(__file__).parent.parent / "rules.yaml").open(encoding="utf-8") as f:
    cc_cert_id_rules = yaml.safe_load(f)


@dataclass
class EUCCCertificate(
    Certificate["EUCCCertificate", "Heuristics", "PdfData"],
    ComplexSerializableType,
):
    """
    Data structure for EUCC certificate. Contains several inner classes that layer the data logic.
    Can be serialized into/from json (`ComplexSerializableType`) or pandas (`PandasSerializableType)`.
    Is basic element of `EUCCDataset`. The functionality is mostly related to holding data and transformations that
    the certificate can handle itself. `EUCCDataset` class then instrument this functionality.
    """

    def __init__(
        self,
        cert_id: str,
        category: str,
        name: str,
        status: str | None,
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
        state: InternalState | None,
        pdf_data: PdfData | None,
        heuristics: Heuristics | None,
        other_metadata: dict[str, str] | None = None,
    ):
        super().__init__()

        self.cert_id = cert_id
        self.category = category
        self.name = sanitization.sanitize_string(name)
        self.status = sanitization.sanitize_string(status) if status else None
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
        self.state = state if state else InternalState()
        self.pdf_data = pdf_data if pdf_data else PdfData()
        self.heuristics = heuristics if heuristics else Heuristics()
        self.other_metadata = other_metadata if other_metadata else None

    @property
    def dgst(self) -> str:
        return dgst(self)

    @property
    def label_studio_title(self) -> str | None:
        return self.name

    @property
    def actual_sars(self) -> set[SAR] | None:
        return actual_sars(self)

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
        set_local_paths(
            self,
            report_pdf_dir,
            st_pdf_dir,
            cert_pdf_dir,
            report_txt_dir,
            st_txt_dir,
            cert_txt_dir,
            report_json_dir,
            st_json_dir,
            cert_json_dir,
        )

    @staticmethod
    def _get_scheme_from_cert_id(cert_id: str) -> str:
        """
        Returns the country code (2-letter) for a given certificate ID
        based on the regex rules in cc_cert_id.yaml.
        """
        cert_id = cert_id.strip()
        cert_id = re.sub(r"^CERTIFICATE[- ]?", "", cert_id, flags=re.IGNORECASE)

        for country, regex_list in cc_cert_id_rules.get("cc_cert_id", {}).items():
            for pattern in regex_list:
                if re.fullmatch(pattern, cert_id):
                    return country
        return ""

    @staticmethod
    def _get_not_valid_before(issuance_date_full: str | None) -> date | None:
        if not issuance_date_full:
            return None
        try:
            not_valid_before = helpers.parse_date(issuance_date_full)
            return not_valid_before
        except Exception:
            return None

    @staticmethod
    def _get_not_valid_after(issuance_date_full: str | None) -> date | None:
        if not issuance_date_full:
            return None
        try:
            issuance_date = helpers.parse_date(issuance_date_full)
            not_valid_after = issuance_date + relativedelta(years=5)
            return not_valid_after
        except Exception:
            return None

    @staticmethod
    def _get_status(date: date | None) -> str | None:
        if not date:
            return None
        today = date.today()
        if date > today:
            return "active"
        else:
            return "archived"

    @staticmethod
    def _extract_holder_website(text: str) -> str:
        url_pattern = r"https?://[a-zA-Z0-9./\-_]+"
        urls = re.findall(url_pattern, text)
        if urls:
            return urls[0]
        return ""

    @staticmethod
    @staticmethod
    def _parse_package(text: str) -> dict[str, list[str]]:
        """
        Parses a string containing CC security packages to extract EALs and components.

        Handles standard CC components (e.g., ADV_FSP.5), non-standard identifiers
        (e.g., COMP), and various separators (commas, 'and', 'augmented with').
        """
        eal_pattern = r"EAL\d+"
        comp_pattern = r"[A-Z]{3,4}(?:_[A-Z]{3,4})?(?:\.\d+)?"

        tokens = re.split(r'(\s+|\(|\)|,|and)', text)

        result = {}
        current_eal = None

        for token in tokens:
            token = token.strip()
            if not token or token in "()," or token.lower() in ["and", "with", "augmented"]:
                continue

            if re.fullmatch(eal_pattern, token):
                current_eal = token
                result[current_eal] = []

            elif re.fullmatch(comp_pattern, token):
                if current_eal:
                    result[current_eal].append(token)

        return result

    def _extract_first_eal(text: str) -> str:
        """
        Finds the first EAL in the text and returns it.
        Returns an empty string or None if no match is found.
        """
        if (not text):
            return ""

        match = re.search(r"EAL\d+", text)

        if match:
            return match.group(0)
        return ""

    @staticmethod
    def _from_metadata_dict(
            certificate_id: str, metadata: dict[str, Any], document_urls: dict[str, str]
    ) -> EUCCCertificate:
        product_type = metadata.get("product_type", "").upper()
        product_name = metadata.get("product_name", "")
        holder_name = metadata.get("holder_name", "")
        scheme = EUCCCertificate._get_scheme_from_cert_id(certificate_id)
        security_level = EUCCCertificate._extract_first_eal(metadata["package"])
        not_valid_before = EUCCCertificate._get_not_valid_before(metadata.get("issuance_date_full"))
        not_valid_after = EUCCCertificate._get_not_valid_after(metadata.get("issuance_date_full"))
        status = EUCCCertificate._get_status(not_valid_after)

        report_link = document_urls.get("certification_report")
        st_link = document_urls.get("security_target")
        cert_link = document_urls.get("certificate")

        holder_website = EUCCCertificate._extract_holder_website(metadata.get("holder_website", ""))

        if "package" in metadata and metadata["package"]:
            metadata["package"] = EUCCCertificate._parse_package(metadata["package"])

        return EUCCCertificate(
            certificate_id,
            product_type,
            product_name,
            status,
            holder_name,
            scheme,
            security_level,
            not_valid_before,
            not_valid_after,
            report_link,
            st_link,
            cert_link,
            holder_website,
            None,
            None,
            None,
            None,
            metadata,
        )

    def compute_heuristics_cert_lab(self):
        compute_heuristics_cert_lab(self)

    def compute_heuristics_version(self) -> None:
        """
        Fills in the heuristically obtained version of certified product into attribute in heuristics class.
        """
        self.heuristics.extracted_versions = helpers.compute_heuristics_version(self.name) if self.name else set()
