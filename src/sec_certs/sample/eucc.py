from __future__ import annotations

from dataclasses import dataclass
from datetime import date

import requests

from sec_certs.sample.cc_eucc_mixin import CC_EUCC_SampleMixin
from sec_certs.sample.certificate import Certificate
from sec_certs.sample.heuristics import Heuristics
from sec_certs.sample.internal_state import InternalState
from sec_certs.sample.pdf_data import PdfData
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.serialization.pandas import PandasSerializableType
from sec_certs.utils import sanitization

SESSION = requests.Session()
SESSION.headers.update(
    {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    }
)

key_map = {
    "Certificate ID": "certificate_id",
    "Name of Product": "product_name",
    "Type of Product": "product_type",
    "Version of Product": "product_version",
    "Name of the Holder": "holder_name",
    "Address of the Holder": "holder_address",
    "Contact Information of the Holder": "holder_contact",
    "Website Holder of Certificate with Supplementary Cybersecurity Information": "holder_website",
    "Name of the certification body that issued the certificate": "certification_body",
    "NANDO ID of the CB": "nando_id",
    "Address of the certification body that issued the certificate": "certification_body_address",
    "Contact information of the certification body that issued the certificate": "certification_body_contact",
    "Name of the ITSEF which performed the evaluation": "itsef",
    "Responsible NCCA": "responsible_ncca",
    "Scheme": "scheme",
    "Reference to the certification report associated with the certificate referred to in Annex V": "report_reference",
    "Assurance level": "assurance_level",
    "CC Version": "cc_version",
    "CEM Version": "cem_version",
    "AVA_VAN Level": "ava_van_level",
    "Package": "package",
    "Protection Profile": "protection_profile",
    "Year of issuance": "issuance_year",
    "Month of Issuance": "issuance_month",
    "ID of the Certificate (yearly number of certificate issued by the CB)": "certificate_yearly_number",
    "Modification/ Reassurance plus the ID": "modification_or_reassurance",
    "period of validity of the certificate": "validity_period_years",
}

FETCH_DELAY_RANGE = (2, 5)


@dataclass
class EUCCCertificate(
    CC_EUCC_SampleMixin,
    Certificate["EUCCCertificate", "Heuristics", "PdfData"],
    PandasSerializableType,
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
        manufacturer: str | None,
        scheme: str | None,
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
