import datetime
import itertools
import logging
import shutil
from pathlib import Path
from typing import Dict, Final, Optional, Set, Union

import numpy as np
import pandas as pd
from bs4 import BeautifulSoup, NavigableString

from sec_certs import constants
from sec_certs.config.configuration import config
from sec_certs.dataset.cpe import CPEDataset
from sec_certs.dataset.cve import CVEDataset
from sec_certs.dataset.dataset import AuxillaryDatasets, Dataset
from sec_certs.dataset.fips_algorithm import FIPSAlgorithmDataset
from sec_certs.model.reference_finder import ReferenceFinder
from sec_certs.model.transitive_vulnerability_finder import TransitiveVulnerabilityFinder
from sec_certs.sample.fips import FIPSCertificate
from sec_certs.serialization.json import ComplexSerializableType, serialize
from sec_certs.utils import helpers
from sec_certs.utils import parallel_processing as cert_processing
from sec_certs.utils.helpers import fips_dgst

logger = logging.getLogger(__name__)


class FIPSAuxillaryDatasets(AuxillaryDatasets):
    cpe_dset: Optional[CPEDataset] = None
    cve_dset: Optional[CVEDataset] = None
    algorithm_dset: Optional[FIPSAlgorithmDataset] = None


class FIPSDataset(Dataset[FIPSCertificate, FIPSAuxillaryDatasets], ComplexSerializableType):
    """
    Class for processing of FIPSCertificate samples. Inherits from `ComplexSerializableType` and base abstract `Dataset` class.
    """

    def __init__(
        self,
        certs: Dict[str, FIPSCertificate] = dict(),
        root_dir: Union[str, Path] = constants.DUMMY_NONEXISTING_PATH,
        name: Optional[str] = None,
        description: str = None,
        state: Optional[Dataset.DatasetInternalState] = None,
        auxillary_datasets: Optional[FIPSAuxillaryDatasets] = None,
    ):
        self.certs = certs
        self._root_dir = Path(root_dir)
        self.timestamp = datetime.datetime.now()
        self.sha256_digest = "not implemented"
        self.name = name if name else type(self).__name__ + " dataset"
        self.description = description if description else datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        self.state = state if state else self.DatasetInternalState()
        self.auxillary_datasets: FIPSAuxillaryDatasets = (
            auxillary_datasets if auxillary_datasets else FIPSAuxillaryDatasets()
        )

    LIST_OF_CERTS_HTML: Final[Dict[str, str]] = {
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
    def algorithms_dir(self) -> Path:
        return self.auxillary_datasets_dir / "algorithms"

    @property
    def algorithm_dataset_path(self) -> Path:
        return self.algorithms_dir / "algorithms.json"

    def __getitem__(self, item: str) -> FIPSCertificate:
        if len(item) < 5:
            return super().__getitem__(fips_dgst(item))
        else:
            return super().__getitem__(item)

    def _extract_data_from_html_modules(self, fresh: bool = True) -> None:
        """
        Extracts data from html module file
        :param bool fresh: if all certs should be processed, or only the failed ones. Defaults to True
        """
        certs_to_process = [x for x in self if x.state.module_is_ok_to_analyze(fresh)]
        processed_certs = cert_processing.process_parallel(
            FIPSCertificate.parse_html_module,
            certs_to_process,
            config.n_threads,
            use_threading=False,
            progress_bar_desc="Extracting data from module html",
        )
        self.update_with_certs(processed_certs)

    @serialize
    def _extract_data(self, fresh: bool = True) -> None:
        if fresh:
            for cert in self:
                cert.state.policy_extract_ok = True
                cert.state.module_extract_ok = True

        self._extract_data_from_html_modules(fresh)
        self._extract_policy_pdf_metadata(fresh)
        self._extract_policy_pdf_keywords(fresh)
        self._extract_algorithms_from_policy_tables(fresh)

    def _extract_policy_pdf_keywords(self, fresh: bool = True) -> None:
        certs_to_process = [x for x in self if x.state.policy_is_ok_to_analyze(fresh)]
        processed_certs = cert_processing.process_parallel(
            FIPSCertificate.extract_policy_pdf_keywords,
            certs_to_process,
            config.n_threads,
            use_threading=False,
            progress_bar_desc="Extracting keywords from policy",
        )
        self.update_with_certs(processed_certs)

    def _download_all_artifacts_body(self, fresh: bool = True) -> None:
        self._download_modules(fresh)
        self._download_policies(fresh)

    def _download_modules(self, fresh: bool = True) -> None:
        logger.info("Downloading HTML cryptographic modules.")
        self.module_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.module_is_ok_to_download(fresh)]
        cert_processing.process_parallel(
            FIPSCertificate.download_module,
            certs_to_process,
            config.n_threads,
            progress_bar_desc="Downloading HTML modules",
        )

    def _download_policies(self, fresh: bool = True) -> None:
        logger.info("Downloading PDF security policies.")
        self.policies_pdf_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.policy_is_ok_to_download(fresh)]
        cert_processing.process_parallel(
            FIPSCertificate.download_policy,
            certs_to_process,
            config.n_threads,
            progress_bar_desc="Downloading PDF security policies",
        )

    def _convert_all_pdfs_body(self, fresh: bool = True) -> None:
        self._convert_policies_to_txt(fresh)

    def _convert_policies_to_txt(self, fresh: bool = True) -> None:
        if fresh:
            logger.info("Converting FIPS security policies to .txt")
        else:
            logger.info("Attempting re-conversion of failed PDF security policies to .txt")

        self.policies_txt_dir.mkdir(parents=True, exist_ok=True)
        certs_to_process = [x for x in self if x.state.policy_is_ok_to_convert(fresh)]
        cert_processing.process_parallel(
            FIPSCertificate.convert_policy_pdf,
            certs_to_process,
            config.n_threads,
            progress_bar_desc="Converting policies to pdf",
        )

    def _download_html_resources(self) -> None:
        logger.info("Downloading HTML files that list FIPS certificates.")
        html_urls = list(FIPSDataset.LIST_OF_CERTS_HTML.values())
        html_paths = [self.web_dir / x for x in FIPSDataset.LIST_OF_CERTS_HTML.keys()]
        helpers.download_parallel(html_urls, html_paths)

    def _get_all_certs_from_html_sources(self) -> Set[FIPSCertificate]:
        return set(
            itertools.chain.from_iterable(
                [self._get_certificates_from_html(self.web_dir / x) for x in self.LIST_OF_CERTS_HTML.keys()]
            )
        )

    def _get_certificates_from_html(self, html_file: Path) -> Set[FIPSCertificate]:
        logger.debug(f"Getting certificate ids from {html_file}")

        with open(html_file, "r", encoding="utf-8") as handle:
            html = BeautifulSoup(handle.read(), "html5lib")

        table = [x for x in html.find(id="searchResultsTable").tbody.contents if x != "\n"]
        cert_ids: Set[str] = set()

        for entry in table:
            if isinstance(entry, NavigableString):
                continue
            cert_id = entry.find("a").text
            if cert_id not in cert_ids:
                cert_ids.add(cert_id)

        return {FIPSCertificate(cert_id) for cert_id in cert_ids}

    @classmethod
    def from_web_latest(cls) -> "FIPSDataset":
        """
        Fetches the fresh snapshot of FIPSDataset from mirror.
        """
        return cls.from_web(config.cc_latest_snapshot, "Downloading FIPS Dataset", "fips_latest_dataset.json")

    def _set_local_paths(self) -> None:
        cert: FIPSCertificate
        for cert in self.certs.values():
            cert.set_local_paths(self.policies_pdf_dir, self.policies_txt_dir, self.module_dir)

        super()._set_local_paths()
        if self.auxillary_datasets.algorithm_dset:
            self.auxillary_datasets.algorithm_dset.json_path = self.algorithm_dataset_path

    @serialize
    def get_certs_from_web(self, to_download: bool = True, keep_metadata: bool = True) -> None:
        self.web_dir.mkdir(parents=True, exist_ok=True)

        if to_download:
            self._download_html_resources()

        logger.info("Adding empty FIPS certificates into FIPSDataset.")
        self.certs = {x.dgst: x for x in self._get_all_certs_from_html_sources()}
        logger.info(f"The dataset now contains {len(self)} certificates.")

        if not keep_metadata:
            shutil.rmtree(self.web_dir)

        self._set_local_paths()
        self.state.meta_sources_parsed = True

    @serialize
    def process_auxillary_datasets(self, download_fresh: bool = False) -> None:
        self.auxillary_datasets.algorithm_dset = self._prepare_algorithm_dataset(download_fresh)
        super().process_auxillary_datasets(download_fresh)

    def _prepare_algorithm_dataset(self, download_fresh_algs: bool = False) -> FIPSAlgorithmDataset:
        logger.info("Preparing FIPSAlgorithm dataset.")
        self.algorithms_dir.mkdir(parents=True, exist_ok=True)

        if not self.algorithm_dataset_path.exists() or download_fresh_algs:
            alg_dset = FIPSAlgorithmDataset.from_web(self.algorithm_dataset_path)
            alg_dset.to_json()
        else:
            alg_dset = FIPSAlgorithmDataset.from_json(self.algorithm_dataset_path)

        return alg_dset

    def _extract_algorithms_from_policy_tables(self, fresh: bool = True):
        certs_to_process = [x for x in self if x.state.policy_is_ok_to_analyze(fresh)]
        cert_processing.process_parallel(
            FIPSCertificate.get_algorithms_from_policy_tables,
            certs_to_process,
            config.n_threads,
            use_threading=False,
            progress_bar_desc="Extracting Algorithms from policy tables",
        )

    def _extract_policy_pdf_metadata(self, fresh: bool = True) -> None:
        certs_to_process = [x for x in self if x.state.policy_is_ok_to_analyze(fresh)]
        processed_certs = cert_processing.process_parallel(
            FIPSCertificate.extract_policy_pdf_metadata,
            certs_to_process,
            config.n_threads,
            use_threading=False,
            progress_bar_desc="Extracting security policy metadata",
        )
        self.update_with_certs(processed_certs)

    def _compute_transitive_vulnerabilities(self) -> None:
        logger.info("Computing transitive vulnerabilities in referenc(ed/ing) certificates.")
        transitive_cve_finder = TransitiveVulnerabilityFinder(lambda cert: cert.cert_id)
        transitive_cve_finder.fit(self.certs, lambda cert: cert.heuristics.policy_processed_references)

        for dgst in self.certs:
            transitive_cve = transitive_cve_finder.predict_single_cert(dgst)
            self.certs[dgst].heuristics.direct_transitive_cves = transitive_cve.direct_transitive_cves
            self.certs[dgst].heuristics.indirect_transitive_cves = transitive_cve.indirect_transitive_cves

    def _prune_reference_candidates(self) -> None:
        for cert in self:
            cert.prune_referenced_cert_ids()

        # Previously, a following procedure was used to prune reference_candidates:
        #   - A set of algorithms was obtained via self.auxillary_datasets.algorithm_dset.get_algorithms_by_id(reference_candidate)
        #   - If any of these algorithms had the same vendor as the reference_candidate, the candidate was rejected
        #   - The rationale is that if an ID appears in a certificate s.t. an algorithm with the same ID was produced by the same vendor, the reference likely refers to alg.
        #   - Such reference should then be discarded.
        #   - We are uncertain of the effectivity of such measure, disabling it for now.

    def _compute_references(self, fresh: bool = True, keep_unknowns: bool = False) -> None:
        self._prune_reference_candidates()

        policy_reference_finder = ReferenceFinder()
        policy_reference_finder.fit(
            self.certs, lambda cert: cert.cert_id, lambda cert: cert.heuristics.policy_prunned_references
        )

        module_reference_finder = ReferenceFinder()
        module_reference_finder.fit(
            self.certs, lambda cert: cert.cert_id, lambda cert: cert.heuristics.module_prunned_references
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

        df.date_validation = pd.to_datetime(df.date_validation, infer_datetime_format=True)
        df.date_sunset = pd.to_datetime(df.date_sunset, infer_datetime_format=True)

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
