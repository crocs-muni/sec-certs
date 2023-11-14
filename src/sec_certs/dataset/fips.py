from __future__ import annotations

import datetime
import itertools
import logging
import shutil
from pathlib import Path
from typing import Final

import numpy as np
import pandas as pd
from bs4 import BeautifulSoup, NavigableString

from sec_certs import constants
from sec_certs.configuration import config
from sec_certs.dataset.cpe import CPEDataset
from sec_certs.dataset.cve import CVEDataset
from sec_certs.dataset.dataset import AuxiliaryDatasets, Dataset
from sec_certs.dataset.fips_algorithm import FIPSAlgorithmDataset
from sec_certs.model.reference_finder import ReferenceFinder
from sec_certs.model.transitive_vulnerability_finder import TransitiveVulnerabilityFinder
from sec_certs.sample.fips import FIPSCertificate
from sec_certs.serialization.json import ComplexSerializableType, serialize
from sec_certs.utils import helpers
from sec_certs.utils import parallel_processing as cert_processing
from sec_certs.utils.helpers import fips_dgst
from sec_certs.utils.profiling import staged

logger = logging.getLogger(__name__)


class FIPSAuxiliaryDatasets(AuxiliaryDatasets):
    cpe_dset: CPEDataset | None = None
    cve_dset: CVEDataset | None = None
    algorithm_dset: FIPSAlgorithmDataset | None = None


class FIPSDataset(Dataset[FIPSCertificate, FIPSAuxiliaryDatasets], ComplexSerializableType):
    """
    Class for processing of FIPSCertificate samples. Inherits from `ComplexSerializableType` and base abstract `Dataset` class.
    """

    def __init__(
        self,
        certs: dict[str, FIPSCertificate] = {},
        root_dir: str | Path = constants.DUMMY_NONEXISTING_PATH,
        name: str | None = None,
        description: str = "",
        state: Dataset.DatasetInternalState | None = None,
        auxiliary_datasets: FIPSAuxiliaryDatasets | None = None,
    ):
        self.certs = certs
        self.timestamp = datetime.datetime.now()
        self.sha256_digest = "not implemented"
        self.name = name if name else type(self).__name__ + " dataset"
        self.description = description if description else datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        self.state = state if state else self.DatasetInternalState()
        self.auxiliary_datasets: FIPSAuxiliaryDatasets = (
            auxiliary_datasets if auxiliary_datasets else FIPSAuxiliaryDatasets()
        )

        self.root_dir = Path(root_dir)

    LIST_OF_CERTS_HTML: Final[dict[str, str]] = {
        "fips_modules_active.html": constants.FIPS_ACTIVE_MODULES_URL,
        "fips_modules_historical.html": constants.FIPS_HISTORICAL_MODULES_URL,
        "fips_modules_revoked.html": constants.FIPS_REVOKED_MODULES_URL,
    }

    @property
    def policies_dir(self) -> Path:
        return self.certs_dir / "policies"

    @property
    def policies_pdf_dir(self) -> Path:
        return self.policies_dir / "pdf"

    @property
    def policies_txt_dir(self) -> Path:
        return self.policies_dir / "txt"

    @property
    def module_dir(self) -> Path:
        return self.certs_dir / "modules"

    @property
    def algorithm_dataset_path(self) -> Path:
        return self.auxiliary_datasets_dir / "algorithms.json"

    def __getitem__(self, item: str) -> FIPSCertificate:
        try:
            return super().__getitem__(item)
        except KeyError:
            return super().__getitem__(fips_dgst(item))

    def _extract_data_from_html_modules(self) -> None:
        """
        Extracts data from html module file
        :param bool fresh: if all certs should be processed, or only the failed ones. Defaults to True
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

    @serialize
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

    def _convert_all_pdfs_body(self, fresh: bool = True) -> None:
        self._convert_policies_to_txt(fresh)

    def _convert_policies_to_txt(self, fresh: bool = True) -> None:
        self.policies_txt_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.policy_is_ok_to_convert(fresh)]

        if fresh:
            logger.info("Converting FIPS security policies to .txt")
        if not fresh and certs_to_process:
            logger.info(
                f"Converting {len(certs_to_process)} FIPS security polcies to .txt for which previous convert failed."
            )

        cert_processing.process_parallel(
            FIPSCertificate.convert_policy_pdf,
            certs_to_process,
            progress_bar_desc="Converting policies to pdf",
        )

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

    @classmethod
    def from_web_latest(cls) -> FIPSDataset:
        """
        Fetches the fresh snapshot of FIPSDataset from mirror.
        """
        return cls.from_web(config.fips_latest_snapshot, "Downloading FIPS Dataset", "fips_latest_dataset.json")

    def _set_local_paths(self) -> None:
        super()._set_local_paths()
        if self.auxiliary_datasets.algorithm_dset:
            self.auxiliary_datasets.algorithm_dset.json_path = self.algorithm_dataset_path

        cert: FIPSCertificate
        for cert in self.certs.values():
            cert.set_local_paths(self.policies_pdf_dir, self.policies_txt_dir, self.module_dir)

    @serialize
    @staged(logger, "Downloading and processing certificates.")
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

    @serialize
    def process_auxiliary_datasets(self, download_fresh: bool = False) -> None:
        super().process_auxiliary_datasets(download_fresh)
        self.auxiliary_datasets.algorithm_dset = self._prepare_algorithm_dataset(download_fresh)

    @staged(logger, "Processing FIPSAlgorithm dataset.")
    def _prepare_algorithm_dataset(self, download_fresh_algs: bool = False) -> FIPSAlgorithmDataset:
        if not self.algorithm_dataset_path.exists() or download_fresh_algs:
            alg_dset = FIPSAlgorithmDataset.from_web(self.algorithm_dataset_path)
            alg_dset.to_json()
        else:
            alg_dset = FIPSAlgorithmDataset.from_json(self.algorithm_dataset_path)

        return alg_dset

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

    @staged(logger, "Computing heuristics: Transitive vulnerabilities in referenc(ed/ing) certificates.")
    def _compute_transitive_vulnerabilities(self) -> None:
        transitive_cve_finder = TransitiveVulnerabilityFinder(lambda cert: str(cert.cert_id))
        transitive_cve_finder.fit(self.certs, lambda cert: cert.heuristics.policy_processed_references)

        for dgst in self.certs:
            transitive_cve = transitive_cve_finder.predict_single_cert(dgst)
            self.certs[dgst].heuristics.direct_transitive_cves = transitive_cve.direct_transitive_cves
            self.certs[dgst].heuristics.indirect_transitive_cves = transitive_cve.indirect_transitive_cves

    @staged(logger, "Computing heuristics: references between certificates.")
    def _compute_references(self, keep_unknowns: bool = False) -> None:
        # Previously, a following procedure was used to prune reference_candidates:
        #   - A set of algorithms was obtained via self.auxiliary_datasets.algorithm_dset.get_algorithms_by_id(reference_candidate)
        #   - If any of these algorithms had the same vendor as the reference_candidate, the candidate was rejected
        #   - The rationale is that if an ID appears in a certificate s.t. an algorithm with the same ID was produced by the same vendor, the reference likely refers to alg.
        #   - Such reference should then be discarded.
        #   - We are uncertain of the effectivity of such measure, disabling it for now.
        for cert in self:
            cert.prune_referenced_cert_ids()

        policy_reference_finder = ReferenceFinder()
        policy_reference_finder.fit(
            self.certs, lambda cert: str(cert.cert_id), lambda cert: cert.heuristics.policy_prunned_references
        )

        module_reference_finder = ReferenceFinder()
        module_reference_finder.fit(
            self.certs, lambda cert: str(cert.cert_id), lambda cert: cert.heuristics.module_prunned_references
        )

        for cert in self:
            cert.heuristics.policy_processed_references = policy_reference_finder.predict_single_cert(
                cert.dgst, keep_unknowns
            )
            cert.heuristics.module_processed_references = module_reference_finder.predict_single_cert(
                cert.dgst, keep_unknowns
            )

    def to_pandas(self) -> pd.DataFrame:
        df = pd.DataFrame([x.pandas_tuple for x in self.certs.values()], columns=FIPSCertificate.pandas_columns)
        df = df.set_index("dgst")

        df.date_validation = pd.to_datetime(df.date_validation, infer_datetime_format=True, errors="coerce")
        df.date_sunset = pd.to_datetime(df.date_sunset, infer_datetime_format=True, errors="coerce")

        # Manually delete one certificate with bad embodiment (seems to have many blank fields)
        df = df.loc[~(df.embodiment == "*")]

        df = df.astype(
            {"type": "category", "status": "category", "standard": "category", "embodiment": "category"}
        ).fillna(value=np.nan)

        df.level = df.level.fillna(value=np.nan).astype("float")
        # df.level = pd.Categorical(df.level, categories=sorted(df.level.dropna().unique().tolist()), ordered=True)

        # Introduce year when cert got valid
        df["year_from"] = pd.DatetimeIndex(df.date_validation).year

        return df
