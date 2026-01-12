import random
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from src.sec_certs import constants

from sec_certs.dataset.auxiliary_dataset_handling import (
    AuxiliaryDatasetHandler,
    CCSchemeDatasetHandler,
    CPEDatasetHandler,
    CPEMatchDictHandler,
    CVEDatasetHandler,
    ProtectionProfileDatasetHandler,
)
from sec_certs.dataset.dataset import Dataset, logger
from sec_certs.sample.eucc import EUCCCertificate
from sec_certs.serialization.json import ComplexSerializableType, only_backed

FETCH_DELAY_RANGE = (2, 5)

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
})

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



class EUCCDataset(Dataset[EUCCCertificate], ComplexSerializableType):
    """
    Class that holds :class:`sec_certs.sample.cc.EUCCCertificate` samples.

    Serializable into json, pandas, dictionary. Conveys basic certificate manipulations
    and dataset transformations. Many private methods that perform internal operations, feel free to exploit them.

    The dataset directory looks like this:

    └── dataset.json
    """
    def __init__(
        self,
        certs: dict[str, EUCCCertificate] | None = None,
        root_dir: str | Path | None = "root_dir",
        name: str | None = None,
        description: str = "",
        state: Dataset.DatasetInternalState | None = None,
        aux_handlers: dict[type[AuxiliaryDatasetHandler], AuxiliaryDatasetHandler] | None = None,
    ):
        super().__init__(certs, root_dir, name, description, state, aux_handlers)
        if aux_handlers is None:
            self.aux_handlers = {
                CPEDatasetHandler: CPEDatasetHandler(self.auxiliary_datasets_dir if self.is_backed else None),
                CVEDatasetHandler: CVEDatasetHandler(self.auxiliary_datasets_dir if self.is_backed else None),
                CPEMatchDictHandler: CPEMatchDictHandler(self.auxiliary_datasets_dir if self.is_backed else None),
                CCSchemeDatasetHandler: CCSchemeDatasetHandler(self.auxiliary_datasets_dir if self.is_backed else None),
                ProtectionProfileDatasetHandler: ProtectionProfileDatasetHandler(
                    self.auxiliary_datasets_dir if self.is_backed else None
                ),

            }

    @property
    @only_backed(throw=False)
    def reports_dir(self) -> Path:
        """
        Returns directory that holds files associated with certification reports
        """
        return self.certs_dir / "reports"

    @property
    @only_backed(throw=False)
    def reports_pdf_dir(self) -> Path:
        """
        Returns directory that holds PDFs associated with certification reports
        """
        return self.reports_dir / "pdf"

    @property
    @only_backed(throw=False)
    def reports_txt_dir(self) -> Path:
        """
        Returns directory that holds TXTs associated with certification reports
        """
        return self.reports_dir / "txt"

    @property
    @only_backed(throw=False)
    def targets_dir(self) -> Path:
        """
        Returns directory that holds files associated with security targets
        """
        return self.certs_dir / "targets"

    @property
    @only_backed(throw=False)
    def targets_pdf_dir(self) -> Path:
        """
        Returns directory that holds PDFs associated with security targets
        """
        return self.targets_dir / "pdf"

    @property
    @only_backed(throw=False)
    def targets_txt_dir(self) -> Path:
        """
        Returns directory that holds TXTs associated with security targets
        """
        return self.targets_dir / "txt"

    @property
    @only_backed(throw=False)
    def certificates_dir(self) -> Path:
        """
        Returns directory that holds files associated with the certificates
        """
        return self.certs_dir / "certificates"

    @property
    @only_backed(throw=False)
    def certificates_pdf_dir(self) -> Path:
        """
        Returns directory that holds PDFs associated with certificates
        """
        return self.certificates_dir / "pdf"

    @property
    @only_backed(throw=False)
    def certificates_txt_dir(self) -> Path:
        """
        Returns directory that holds TXTs associated with certificates
        """
        return self.certificates_dir / "txt"

    def _fetch_delay(self) -> None:
        """
        Random delay to avoid overloading the server
        """
        time.sleep(random.uniform(*FETCH_DELAY_RANGE))


    def _get_certificates_links(self) -> list[str]:
        """
        Extract all certificate detail page links from the EUCC base page
        """
        soup = self._get_soup(constants.EUCC_BASE_URL)

        links = []
        for a in soup.select("main a"):
            href = a.get("href")
            text = a.get_text(strip=True)
            if href and ("certificate" in href.lower() or text.startswith("EUCC-")):
                links.append(urljoin(constants.EUCC_BASE_URL, href))

        unique_links = sorted(set(links))

        self._fetch_delay()
        return unique_links

    def _parse_page_metadata(self, cert_soup: BeautifulSoup) -> dict[str, str]:
        """
        Extract key-value metadata pairs from a certificate details page
        """

        table = cert_soup.select_one("div.ecl div.ecl-table-responsive table.ecl-table")
        metadata = {}

        if not table:
            return metadata

        for row in table.select("tr"):
            tds = row.find_all("td")
            if len(tds) != 2:
                continue
            key = tds[0].get_text(strip=True)
            value = tds[1].get_text(strip=True)

            if key in key_map:
                metadata[key_map[key]] = value

        return metadata

    def _get_page_metadata(self, links: list[str]) -> list[dict[str, Any]]:
        """
        Visit each certificate link and extract metadata
        """
        results = []

        for i, link in enumerate(links, start=1):
            try:
                cert_soup = self._get_soup(link)
                metadata = self._parse_page_metadata(cert_soup)
                results.append({"url": link, "metadata": metadata})

            finally:
                self._fetch_delay()

        return results

    def get_certs_from_web(
        self,
        to_download: bool = True,
    ) -> None:
        """
        Downloads CSV and HTML files that hold lists of certificates from ENISA website. Parses these files
        and constructs EUCC objects, fills the dataset with those.

        :param bool to_download: If fresh data shall be downloaded (or existing files utilized), defaults to True
        """

        links = self._get_certificates_links()
        self.certs = self._get_page_metadata(links)
        logger.info(f"The resulting dataset has {len(self)} certificates.")
