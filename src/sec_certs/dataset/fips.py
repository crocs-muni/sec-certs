from __future__ import annotations

import itertools
import logging
import shutil
from pathlib import Path
from typing import ClassVar, Final

import numpy as np
import pandas as pd
from bs4 import BeautifulSoup, NavigableString
from pydantic import AnyHttpUrl

from sec_certs import constants
from sec_certs.configuration import config
from sec_certs.dataset.auxiliary_dataset_handling import (
    AuxiliaryDatasetHandler,
    CPEDatasetHandler,
    CPEMatchDictHandler,
    CVEDatasetHandler,
    FIPSAlgorithmDatasetHandler,
)
from sec_certs.dataset.dataset import Dataset
from sec_certs.heuristics.common import compute_cpe_heuristics, compute_related_cves, compute_transitive_vulnerabilities
from sec_certs.heuristics.fips import compute_references
from sec_certs.sample.fips import FIPSCertificate
from sec_certs.serialization.json import ComplexSerializableType, only_backed, serialize
from sec_certs.utils import helpers
from sec_certs.utils import parallel_processing as cert_processing
from sec_certs.utils.helpers import fips_dgst
from sec_certs.utils.pdf import PDFConverter
from sec_certs.utils.profiling import staged
from sec_certs.utils.tqdm import tqdm

logger = logging.getLogger(__name__)


class FIPSDataset(Dataset[FIPSCertificate], ComplexSerializableType):
    """
    Class for processing of :class:`sec_certs.sample.fips.FIPSCertificate` samples.

    Inherits from `ComplexSerializableType` and base abstract `Dataset` class.

    The dataset directory looks like this:

        ├── auxiliary_datasets
        │   ├── cpe_dataset.json
        │   ├── cve_dataset.json
        │   ├── cpe_match.json
        │   └── algorithms.json
        ├── certs
        │   └── targets
        │       ├── pdf
        │       ├── txt
        │       └── json
        └── dataset.json
    """

    FULL_ARCHIVE_URL: ClassVar[AnyHttpUrl] = config.fips_latest_full_archive
    SNAPSHOT_URL: ClassVar[AnyHttpUrl] = config.fips_latest_snapshot

    def __init__(
        self,
        certs: dict[str, FIPSCertificate] | None = None,
        root_dir: str | Path | None = None,
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
                FIPSAlgorithmDatasetHandler: FIPSAlgorithmDatasetHandler(
                    self.auxiliary_datasets_dir if self.is_backed else None
                ),
                CPEMatchDictHandler: CPEMatchDictHandler(self.auxiliary_datasets_dir if self.is_backed else None),
            }

    LIST_OF_CERTS_HTML: Final[dict[str, str]] = {
        "fips_modules_active.html": constants.FIPS_ACTIVE_MODULES_URL,
        "fips_modules_historical.html": constants.FIPS_HISTORICAL_MODULES_URL,
        "fips_modules_revoked.html": constants.FIPS_REVOKED_MODULES_URL,
    }

    @property
    @only_backed(throw=False)
    def policies_dir(self) -> Path:
        return self.certs_dir / "policies"

    @property
    @only_backed(throw=False)
    def policies_pdf_dir(self) -> Path:
        return self.policies_dir / "pdf"

    @property
    @only_backed(throw=False)
    def policies_txt_dir(self) -> Path:
        return self.policies_dir / "txt"

    @property
    @only_backed(throw=False)
    def policies_json_dir(self) -> Path:
        return self.policies_dir / "json"

    @property
    @only_backed(throw=False)
    def module_dir(self) -> Path:
        return self.certs_dir / "modules"

    def __getitem__(self, item: str) -> FIPSCertificate:
        try:
            return super().__getitem__(item)
        except KeyError:
            return super().__getitem__(fips_dgst(item))

    def _extract_data_from_html_modules(self) -> None:
        """
        Extracts data from html module file
        """
        logger.info("Extracting data from html modules.")
        certs_to_process = [x for x in self if x.state.module_is_ok_to_analyze()]
        processed_certs = cert_processing.process_parallel(
            FIPSCertificate.parse_html_module,
            certs_to_process,
            use_threading=False,
            progress_bar_desc="Extracting data from html modules",
        )
        self.update_with_certs(processed_certs)

    def _compute_heuristics_body(self):
        compute_cpe_heuristics(self.aux_handlers[CPEDatasetHandler].dset, self.certs.values())
        compute_related_cves(
            self.aux_handlers[CPEDatasetHandler].dset,
            self.aux_handlers[CVEDatasetHandler].dset,
            self.aux_handlers[CPEMatchDictHandler].dset,
            self.certs.values(),
        )
        compute_references(self.certs)
        compute_transitive_vulnerabilities(self.certs)

    @serialize
    @only_backed()
    def extract_data(self) -> None:
        logger.info("Extracting various data from certification artifacts.")
        for cert in self:
            cert.state.policy_extract_ok = True
            cert.state.module_extract_ok = True

        self._extract_data_from_html_modules()
        self._extract_policy_pdf_metadata()
        self._extract_policy_pdf_keywords()
        self._extract_algorithms_from_policy_tables()

    def _extract_policy_pdf_keywords(self) -> None:
        logger.info("Extracting keywords from policy pdfs.")
        certs_to_process = [x for x in self if x.state.policy_is_ok_to_analyze()]
        processed_certs = cert_processing.process_parallel(
            FIPSCertificate.extract_policy_pdf_keywords,
            certs_to_process,
            use_threading=False,
            progress_bar_desc="Extracting keywords from policy pdfs",
        )
        self.update_with_certs(processed_certs)

    def _download_all_artifacts_body(self, fresh: bool = True) -> None:
        self._download_modules(fresh)
        self._download_policies(fresh)

    def _download_modules(self, fresh: bool = True) -> None:
        self.module_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.module_is_ok_to_download(fresh)]

        if fresh:
            logger.info("Downloading HTML cryptographic modules.")
        if not fresh and certs_to_process:
            logger.info(f"Downloading {len(certs_to_process)} HTML modules for which download failed.")

        cert_processing.process_parallel(
            FIPSCertificate.download_module,
            certs_to_process,
            progress_bar_desc="Downloading HTML modules",
        )

    def _download_policies(self, fresh: bool = True) -> None:
        self.policies_pdf_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.policy_is_ok_to_download(fresh)]

        if fresh:
            logger.info("Downloading PDF security policies.")
        if not fresh and certs_to_process:
            logger.info(f"Downloading {len(certs_to_process)} PDF security policies for which download failed.")

        cert_processing.process_parallel(
            FIPSCertificate.download_policy,
            certs_to_process,
            progress_bar_desc="Downloading PDF security policies",
        )

    def _convert_all_pdfs_body(self, converter: PDFConverter, fresh: bool = True) -> None:
        self._convert_policies_pdfs(converter, fresh)

    @staged(logger, "Converting PDFs of FIPS security policies.")
    def _convert_policies_pdfs(self, converter: PDFConverter, fresh: bool = True) -> None:
        self.policies_txt_dir.mkdir(parents=True, exist_ok=True)
        self.policies_json_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.policy_is_ok_to_convert(fresh)]

        if not certs_to_process:
            logger.info("No FIPS security policies need conversion.")
            return
        if not fresh and certs_to_process:
            logger.info(
                f"Converting {len(certs_to_process)} PDFs of FIPS security policies for which previous conversion failed."
            )

        progress_bar = tqdm(total=len(certs_to_process), desc="Converting PDFs of FIPS security policies")
        for cert in certs_to_process:
            FIPSCertificate.convert_policy_pdf(cert, converter)
            progress_bar.update(1)

        progress_bar.close()

    def _download_html_resources(self) -> None:
        logger.info("Downloading HTML files that list FIPS certificates.")
        html_urls = list(FIPSDataset.LIST_OF_CERTS_HTML.values())
        html_paths = [self.web_dir / x for x in FIPSDataset.LIST_OF_CERTS_HTML]
        helpers.download_parallel(html_urls, html_paths)

    def _get_all_certs_from_html_sources(self) -> list[FIPSCertificate]:
        return list(
            itertools.chain.from_iterable(
                self._get_certificates_from_html(self.web_dir / x) for x in self.LIST_OF_CERTS_HTML
            )
        )

    def _get_certificates_from_html(self, html_file: Path) -> list[FIPSCertificate]:
        with html_file.open("r", encoding="utf-8") as handle:
            html = BeautifulSoup(handle.read(), "html5lib")

        table = [x for x in html.find(id="searchResultsTable").tbody.contents if x != "\n"]
        cert_ids: set[str] = set()

        for entry in table:
            if isinstance(entry, NavigableString):
                continue
            cert_id = entry.find("a").text
            if cert_id not in cert_ids:
                cert_ids.add(cert_id)

        return [FIPSCertificate(int(cert_id)) for cert_id in cert_ids]

    def _set_local_paths(self) -> None:
        super()._set_local_paths()
        if self.root_dir is None:
            return
        for cert in self:
            cert.set_local_paths(self.policies_pdf_dir, self.policies_txt_dir, self.policies_json_dir, self.module_dir)

    @serialize
    @staged(logger, "Downloading and processing certificates.")
    @only_backed()
    def get_certs_from_web(self, to_download: bool = True, keep_metadata: bool = True) -> None:
        self.web_dir.mkdir(parents=True, exist_ok=True)

        if to_download:
            self._download_html_resources()

        self.certs = {x.dgst: x for x in self._get_all_certs_from_html_sources()}
        logger.info(f"The dataset now contains {len(self)} certificates.")

        if not keep_metadata:
            shutil.rmtree(self.web_dir)

        self._set_local_paths()
        self.state.meta_sources_parsed = True

    @staged(logger, "Extracting Algorithms from policy tables")
    def _extract_algorithms_from_policy_tables(self):
        certs_to_process = [x for x in self if x.state.policy_is_ok_to_analyze()]
        cert_processing.process_parallel(
            FIPSCertificate.get_algorithms_from_policy_tables,
            certs_to_process,
            use_threading=False,
            progress_bar_desc="Extracting Algorithms from policy tables",
        )

    @staged(logger, "Extracting security policy metadata from the pdfs")
    def _extract_policy_pdf_metadata(self) -> None:
        certs_to_process = [x for x in self if x.state.policy_is_ok_to_analyze()]
        processed_certs = cert_processing.process_parallel(
            FIPSCertificate.extract_policy_pdf_metadata,
            certs_to_process,
            use_threading=False,
            progress_bar_desc="Extracting security policy metadata",
        )
        self.update_with_certs(processed_certs)

    def to_pandas(self) -> pd.DataFrame:
        df = pd.DataFrame(
            [x.pandas_tuple for x in self.certs.values()],
            columns=FIPSCertificate.pandas_columns,
        )
        df = df.set_index("dgst")

        df.date_validation = pd.to_datetime(df.date_validation, errors="coerce")
        df.date_sunset = pd.to_datetime(df.date_sunset, errors="coerce")

        # Manually delete one certificate with bad embodiment (seems to have many blank fields)
        df = df.loc[~(df.embodiment == "*")]

        df = df.astype(
            {
                "type": "category",
                "status": "category",
                "standard": "category",
                "embodiment": "category",
            }
        ).fillna(value=np.nan)

        df.level = df.level.fillna(value=np.nan).astype("float")
        # df.level = pd.Categorical(df.level, categories=sorted(df.level.dropna().unique().tolist()), ordered=True)

        # Introduce year when cert got valid
        df["year_from"] = pd.DatetimeIndex(df.date_validation).year

        return df
