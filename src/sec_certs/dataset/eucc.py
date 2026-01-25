from __future__ import annotations

import random
import time
from pathlib import Path
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from sec_certs import constants
from sec_certs.converter import PDFConverter
from sec_certs.dataset.auxiliary_dataset_handling import (
    AuxiliaryDatasetHandler,
    CCSchemeDatasetHandler,
    CPEDatasetHandler,
    CPEMatchDictHandler,
    CVEDatasetHandler,
    ProtectionProfileDatasetHandler,
)
from sec_certs.dataset.cc_eucc_common import (
    compute_heuristics_body,
    convert_all_pdfs_body,
    download_all_artifacts_body,
    extract_all_frontpages,
    extract_all_keywords,
    extract_all_metadata,
)
from sec_certs.dataset.dataset import Dataset, logger
from sec_certs.sample.eucc import EUCCCertificate
from sec_certs.serialization.json import ComplexSerializableType, only_backed, serialize
from sec_certs.utils.profiling import staged

FETCH_DELAY_RANGE = (2, 5)

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


class EUCCDataset(Dataset[EUCCCertificate], ComplexSerializableType):
    """
    Class that holds :class:`sec_certs.sample.eucc.EUCCCertificate` samples.

    Serializable into json, pandas, dictionary. Conveys basic certificate manipulations
    and dataset transformations. Many private methods that perform internal operations, feel free to exploit them.

    The dataset directory looks like this:

        ├── auxiliary_datasets
        │   ├── cpe_dataset.json
        │   ├── cve_dataset.json
        │   ├── cpe_match.json
        │   ├── cc_scheme.json
        │   ├── protection_profiles
        │   │   ├── reports
        │   │   │   ├── pdf
        │   │   │   ├── txt
        │   │   │   └── json
        │   │   ├── pps
        │   │   │   ├── pdf
        │   │   │   ├── txt
        │   │   │   └── json
        │   │   └── dataset.json
        ├── certs
        │   ├── reports
        │   │   ├── pdf
        │   │   ├── txt
        │   │   └── json
        │   ├── targets
        │   │   ├── pdf
        │   │   ├── txt
        │   │   └── json
        │   └── certificates
        │       ├── pdf
        │       ├── txt
        │       └── json
        └── dataset.json
    """

    _metadata_key_map = {
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
        "date of issuance": "issuance_date_full",
        "Certificate issue date": "issuance_date_full",
        "ID of the Certificate (yearly number of certificate issued by the CB)": "certificate_yearly_number",
        "Modification/ Reassurance plus the ID": "modification_or_reassurance",
        "period of validity of the certificate": "validity_period_years",
    }

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
    def dataset_name(self) -> str:
        return "EUCC"

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
    def reports_json_dir(self) -> Path:
        """
        Returns directory that holds JSONs associated with certification reports
        """
        return self.reports_dir / "json"

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
    def targets_json_dir(self) -> Path:
        """
        Returns directory that holds JSONs associated with certification targets
        """
        return self.targets_dir / "json"

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

    @property
    @only_backed(throw=False)
    def certificates_json_dir(self) -> Path:
        """
        Returns directory that holds JSONs associated with certification certificates
        """
        return self.certificates_dir / "json"

    def _fetch_delay(self) -> None:
        """
        Random delay to avoid overloading the server.
        """
        time.sleep(random.uniform(*FETCH_DELAY_RANGE))

    def _get_soup(self, url: str) -> BeautifulSoup:
        """
        Fetch a URL and return a BeautifulSoup object.
        """
        resp = SESSION.get(url)
        resp.raise_for_status()
        return BeautifulSoup(resp.content, "html.parser")

    def _download_certificates_links(self) -> list[str]:
        """
        Parses the EUCC base page and extracts URLs pointing to individual certificate detail pages.
        """
        soup = self._get_soup(constants.EUCC_BASE_URL)

        links: set[str] = set()

        for anchor in soup.select("main a"):
            href = anchor.get("href")
            if not href:
                continue

            text = anchor.get_text(strip=True)

            is_certificate_link = "certificate" in href.lower()
            is_eucc_id_link = text.startswith("EUCC-")

            if not (is_certificate_link or is_eucc_id_link):
                continue

            full_url = urljoin(constants.EUCC_BASE_URL, href)
            links.add(full_url)

        self._fetch_delay()
        return sorted(links)

    def _parse_page_metadata(self, cert_soup: BeautifulSoup) -> dict[str, str]:
        """
        Extract key-value metadata pairs from a certificate details page
        """
        table = cert_soup.select_one("div.ecl div.ecl-table-responsive table.ecl-table")

        if not table:
            return {}

        metadata: dict[str, str] = {}

        for row in table.select("tr"):
            cells = row.find_all("td")
            if len(cells) != 2:
                continue

            raw_key = cells[0].get_text(strip=True)
            raw_value = cells[1].get_text(strip=True)
            clean_key = raw_key.strip().rstrip(";")
            mapped_key = self._metadata_key_map.get(clean_key)

            if not mapped_key:
                continue

            metadata[mapped_key] = raw_value

        return metadata

    def _parse_certificate_document_urls(self, cert_soup: BeautifulSoup) -> dict[str, str]:
        """
        Extract URLs of certificate-related documents from a certificate detail page.

        Supported documents include the certificate, security target, and certification report.
        """
        document_urls: dict[str, str] = {}
        document_type_map = {
            "Certificate": "certificate",
            "Security Target": "security_target",
            "Certification Report": "certification_report",
        }

        for label, key in document_type_map.items():
            label_paragraph = cert_soup.find("p", string=label)
            if not label_paragraph:
                continue

            file_container = label_paragraph.find_next("div", class_="ecl-file")
            if not file_container:
                continue

            download_link = file_container.select_one("a.ecl-file__download")
            if not download_link or not download_link.get("href"):
                continue

            document_urls[key] = urljoin(
                constants.EUCC_BASE_URL,
                download_link["href"],
            )

        return document_urls

    def _download_page_metadata(self, links: list[str]) -> dict[str, EUCCCertificate]:
        """
        Iterates over EUCC certificate detail page URLs, downloads and parses their content,
        extracts certificate metadata and document links, and returns a dictionary mapping
        certificate digests to EUCCCertificate objects.
        """
        certificates: dict[str, EUCCCertificate] = {}

        for link in links:
            try:
                soup = self._get_soup(link)

                metadata = self._parse_page_metadata(soup)
                document_urls = self._parse_certificate_document_urls(soup)
                certificate_id = metadata.get("certificate_id")
                if not certificate_id:
                    return {}

                cert = EUCCCertificate._from_metadata_dict(certificate_id, metadata, document_urls)
                certificates[cert.dgst] = cert

            finally:
                self._fetch_delay()

        return certificates

    def _download_metadata(self) -> None:
        """
        Downloads certificate metadata from the ENISA EUCC page and populates the dataset.
        """
        links = self._download_certificates_links()

        logger.info("Downloading certificates metadata.")

        self.certs = self._download_page_metadata(links)

    @serialize
    @staged(logger, "Downloading and processing metadata from ENISA EUCC page.")
    @only_backed()
    def get_certs_from_web(self, to_download: bool = True) -> None:
        """
        Downloads certificate metadata from the ENISA website, parses the downloaded files, and constructs EUCC objects to
        populate the dataset.

        :param bool to_download: If fresh data shall be downloaded (or existing files utilized), defaults to True
        """
        if to_download is True:
            self._download_metadata()

        logger.info(f"The resulting dataset has {len(self)} certificates.")

        self._set_local_paths()
        self.state.meta_sources_parsed = True

    def process_auxiliary_datasets(self, download_fresh: bool = False, skip_schemes: bool = False, **kwargs) -> None:
        if CCSchemeDatasetHandler in self.aux_handlers:
            self.aux_handlers[CCSchemeDatasetHandler].only_schemes = {x.scheme for x in self}  # type: ignore

        if skip_schemes:
            self.aux_handlers[CCSchemeDatasetHandler].only_schemes = {}  # type: ignore
        super().process_auxiliary_datasets(download_fresh, **kwargs)

    def _set_local_paths(self):
        super()._set_local_paths()
        if self.root_dir is None:
            return

        for cert in self:
            cert.set_local_paths(
                self.reports_pdf_dir,
                self.targets_pdf_dir,
                self.certificates_pdf_dir,
                self.reports_txt_dir,
                self.targets_txt_dir,
                self.certificates_txt_dir,
                self.reports_json_dir,
                self.targets_json_dir,
                self.certificates_json_dir,
            )

    def _download_all_artifacts_body(self, fresh: bool = True) -> None:
        download_all_artifacts_body(self, fresh)

    def _convert_all_pdfs_body(self, converter_cls: type[PDFConverter], fresh: bool = True) -> None:
        convert_all_pdfs_body(self, converter_cls, fresh)

    @only_backed()
    def extract_data(self) -> None:
        logger.info("Extracting various data from certification artifacts.")
        extract_all_metadata(self)
        extract_all_frontpages(self)
        extract_all_keywords(self)

    def _compute_heuristics_body(self, skip_schemes: bool = False) -> None:
        compute_heuristics_body(self, skip_schemes)
