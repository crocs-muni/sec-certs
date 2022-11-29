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
from sec_certs.model.dependency_finder import DependencyFinder
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
        cert_ids: Set[int] = set()

        for entry in table:
            if isinstance(entry, NavigableString):
                continue
            cert_id = entry.find("a").text
            if cert_id not in cert_ids:
                cert_ids.add(int(cert_id))

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
    def process_auxillary_datasets(self) -> None:
        self.auxillary_datasets.algorithm_dset = self._prepare_algorithm_dataset()
        super().process_auxillary_datasets()

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

    def _compute_normalized_cert_ids(self, fresh: bool = True) -> None:
        # TODO: Refactor me
        for cert in self.certs.values():
            self._clean_cert_ids(cert)

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

    def _compare_certs(self, current_certificate: FIPSCertificate, other_id: str) -> bool:
        other_dgst = fips_dgst(other_id)
        other_cert = self.certs[other_dgst]

        if (
            current_certificate.web_data.validation_history is None
            or other_cert is None
            or other_cert.web_data.validation_history is None
        ):
            raise RuntimeError("Building of the dataset probably failed - this should not be happening.")

        cert_first = current_certificate.web_data.validation_history[0].date
        cert_last = current_certificate.web_data.validation_history[-1].date
        conn_first = other_cert.web_data.validation_history[0].date
        conn_last = other_cert.web_data.validation_history[-1].date

        return (
            cert_first.year - conn_first.year > config.year_difference_between_validations
            and cert_last.year - conn_last.year > config.year_difference_between_validations
            or cert_first.year < conn_first.year
        )

    def _clean_cert_ids(self, current_cert: FIPSCertificate) -> None:
        # TODO: Refactor me
        current_cert.clean_cert_ids()
        current_cert.heuristics.clean_cert_ids = {
            cert_id: count
            for cert_id, count in current_cert.pdf_data.clean_cert_ids.items()
            if self._validate_id(current_cert, cert_id.replace("Cert.", "").replace("cert.", "").lstrip("#CA0 "))
            and cert_id != current_cert.cert_id
        }

    def _compute_transitive_vulnerabilities(self, fresh: bool = True) -> None:
        # TODO: Implement me
        pass

    @staticmethod
    def _match_with_algorithm(processed_cert: FIPSCertificate, cert_candidate_id: str) -> bool:
        for algo in processed_cert.heuristics.algorithms:
            curr_id = "".join(filter(str.isdigit, algo))
            if curr_id == cert_candidate_id:
                return False
        return True

    def _validate_id(self, processed_cert: FIPSCertificate, cert_candidate_id: str) -> bool:
        # TODO: Refactor me
        candidate_dgst = fips_dgst(cert_candidate_id)
        if candidate_dgst not in self.certs or not cert_candidate_id.isdecimal():
            return False

        # "< number" still needs to be used, because of some old certs being revalidated
        if int(cert_candidate_id) < config.smallest_certificate_id_to_connect or self._compare_certs(
            processed_cert, cert_candidate_id
        ):
            return False

        if self.auxillary_datasets.algorithm_dset is None:
            raise RuntimeError("Dataset was probably not built correctly - this should not be happening.")

        if not FIPSDataset._match_with_algorithm(processed_cert, cert_candidate_id):
            return False

        algs = self.auxillary_datasets.algorithm_dset.get_algorithms_by_id(cert_candidate_id)
        for current_alg in algs:
            if current_alg.vendor is None or processed_cert.web_data.vendor is None:
                raise RuntimeError("Dataset was probably not built correctly - this should not be happening.")

            if FIPSCertificate.get_compare(processed_cert.web_data.vendor) == FIPSCertificate.get_compare(
                current_alg.vendor
            ):
                return False
        return True

    def _compute_references(self, fresh: bool = True) -> None:
        # TODO: Refactor me
        def pdf_lookup(cert):
            return set(
                filter(
                    lambda x: x,
                    map(
                        lambda cid: "".join(filter(str.isdigit, cid)),
                        cert.heuristics.clean_cert_ids,
                    ),
                )
            )

        def web_lookup(cert):
            return set(
                filter(lambda x: x, map(lambda cid: "".join(filter(str.isdigit, cid)), cert.web_data.mentioned_certs))
            )

        finder = DependencyFinder()
        finder.fit(self.certs, lambda cert: str(cert.cert_id), pdf_lookup)  # type: ignore

        for dgst in self.certs:
            setattr(self.certs[dgst].heuristics, "st_references", finder.predict_single_cert(dgst, keep_unknowns=False))

        finder = DependencyFinder()
        finder.fit(self.certs, lambda cert: str(cert.cert_id), web_lookup)  # type: ignore

        for dgst in self.certs:
            setattr(
                self.certs[dgst].heuristics, "web_references", finder.predict_single_cert(dgst, keep_unknowns=False)
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
