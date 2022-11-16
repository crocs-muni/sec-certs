import itertools
import logging
import shutil
from pathlib import Path
from typing import Dict, Final, List, Set

import numpy as np
import pandas as pd
from bs4 import BeautifulSoup, NavigableString
from graphviz import Digraph

from sec_certs import constants
from sec_certs.config.configuration import config
from sec_certs.dataset.dataset import AuxillaryDatasets, Dataset
from sec_certs.dataset.fips_algorithm import FIPSAlgorithmDataset
from sec_certs.model.dependency_finder import DependencyFinder
from sec_certs.sample.fips import FIPSCertificate
from sec_certs.serialization.json import ComplexSerializableType, serialize
from sec_certs.utils import parallel_processing as cert_processing
from sec_certs.utils.helpers import fips_dgst

logger = logging.getLogger(__name__)


class FIPSDataset(Dataset[FIPSCertificate, AuxillaryDatasets], ComplexSerializableType):
    """
    Class for processing of FIPSCertificate samples. Inherits from `ComplexSerializableType` and base abstract `Dataset` class.
    """

    def __init__(self, *args, **kwargs):
        return super().__init__(*args, **kwargs)

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

    @serialize
    def _extract_data(self, redo: bool = False) -> None:
        """
        Extracts data from pdf files
        :param bool redo: Whether to try again with failed files, defaults to False
        """
        logger.info("Entering PDF scan.")

        keywords = cert_processing.process_parallel(
            FIPSCertificate.find_keywords,
            [cert for cert in self.certs.values() if not cert.pdf_data.keywords or redo],
            config.n_threads,
            use_threading=False,
            progress_bar_desc="Scanning PDF files",
        )
        for keyword, cert in keywords:
            self.certs[cert.dgst].pdf_data.keywords = keyword

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
        self._download_parallel(html_urls, html_paths)

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

    @serialize
    def web_scan(self, cert_ids: Set[str], redo: bool = False) -> None:
        """
        Creates FIPSCertificate object from the relevant html file that must be downlaoded.

        :param Set[str] cert_ids: Cert ids to create FIPSCertificate objects for.
        :param bool redo: whether to re-attempt with failed certificates, defaults to False
        """
        logger.info("Entering web scan.")
        for cert_id in cert_ids:
            dgst = fips_dgst(cert_id)
            self.certs[dgst] = FIPSCertificate.from_html_file(
                self.web_dir / f"{cert_id}.html",
                FIPSCertificate.InternalState(
                    False,
                    False,
                    False,
                ),
                self.certs.get(dgst),
                redo=redo,
            )

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
        self._process_algorithms()
        super().process_auxillary_datasets()

    def _process_algorithms(self):
        logger.info("Processing FIPS algorithms.")
        self.algorithms_dir.mkdir(parernts=True, exist_ok=True)
        self.algorithms = FIPSAlgorithmDataset({}, self.algorithms_dir, "algorithms", "sample algs")
        self.algorithms.get_certs_from_web()
        logger.info(f"Finished parsing. Have algorithm dataset with {len(self.algorithms)} algorithm numbers.")

    @serialize
    def extract_certs_from_tables(self, high_precision: bool) -> List[Path]:
        """
        Function that extracts algorithm IDs from tables in security policies files.
        :return: list of files that couldn't have been decoded
        """
        logger.info("Entering table scan.")
        result = cert_processing.process_parallel(
            FIPSCertificate.analyze_tables,
            [(cert, high_precision) for cert in self.certs.values() if cert is not None and high_precision],
            # TODO: Below is an old version with tables_done, txt_state attribute that we already deleted, rewrite without it
            # FIPSCertificate.analyze_tables
            # [
            #     (cert, high_precision)
            #     for cert in self.certs.values()
            #     if cert is not None and (not cert.state.tables_done or high_precision) and cert.state.txt_state
            # ],
            config.n_threads // 4,  # tabula already processes by parallel, so
            # it's counterproductive to use all threads
            use_threading=False,
            progress_bar_desc="Searching tables",
        )

        not_decoded = [cert.state.sp_path for done, cert, _ in result if done is False]
        for state, cert, algorithms in result:
            certificate = self.certs[cert.dgst]
            # TODO: Fix me, attribute below deleted
            # certificate.state.tables_done = state
            certificate.pdf_data.algorithms = algorithms
        return not_decoded

    def _compute_heuristics_clean_ids(self) -> None:
        for cert in self.certs.values():
            self._clean_cert_ids(cert)

    def _extract_metadata(self):
        certs_to_process = [x for x in self]
        res = cert_processing.process_parallel(
            FIPSCertificate.extract_sp_metadata,
            certs_to_process,
            config.n_threads,
            use_threading=False,
            progress_bar_desc="Extracting security policy metadata",
        )
        for r in res:
            self.certs[r.dgst] = r

    def _unify_algorithms(self) -> None:
        for certificate in self.certs.values():
            certificate.heuristics.algorithms = set()
            if certificate.web_data.algorithms:
                certificate.heuristics.algorithms.update(certificate.web_data.algorithms)
            if certificate.pdf_data.algorithms:
                certificate.heuristics.algorithms.update(certificate.pdf_data.algorithms)

    def _compare_certs(self, current_certificate: FIPSCertificate, other_id: str) -> bool:
        other_dgst = fips_dgst(other_id)
        other_cert = self.certs[other_dgst]

        if (
            current_certificate.web_data.date_validation is None
            or other_cert is None
            or other_cert.web_data.date_validation is None
        ):
            raise RuntimeError("Building of the dataset probably failed - this should not be happening.")

        cert_first = current_certificate.web_data.date_validation[0]
        cert_last = current_certificate.web_data.date_validation[-1]
        conn_first = other_cert.web_data.date_validation[0]
        conn_last = other_cert.web_data.date_validation[-1]

        return (
            cert_first.year - conn_first.year > config.year_difference_between_validations
            and cert_last.year - conn_last.year > config.year_difference_between_validations
            or cert_first.year < conn_first.year
        )

    def _clean_cert_ids(self, current_cert: FIPSCertificate) -> None:
        current_cert.clean_cert_ids()
        # TODO: Fix me, txt state no longer available
        # if not current_cert.state.txt_state:
        #     return
        current_cert.heuristics.clean_cert_ids = {
            cert_id: count
            for cert_id, count in current_cert.pdf_data.clean_cert_ids.items()
            if self._validate_id(current_cert, cert_id.replace("Cert.", "").replace("cert.", "").lstrip("#CA0 "))
            and cert_id != current_cert.cert_id
        }

    @staticmethod
    def _match_with_algorithm(processed_cert: FIPSCertificate, cert_candidate_id: str) -> bool:
        for algo in processed_cert.heuristics.algorithms:
            curr_id = "".join(filter(str.isdigit, algo.cert_id))
            if curr_id == cert_candidate_id:
                return False
        return True

    def _validate_id(self, processed_cert: FIPSCertificate, cert_candidate_id: str) -> bool:
        candidate_dgst = fips_dgst(cert_candidate_id)
        if candidate_dgst not in self.certs or not cert_candidate_id.isdecimal():
            return False

        # "< number" still needs to be used, because of some old certs being revalidated
        if int(cert_candidate_id) < config.smallest_certificate_id_to_connect or self._compare_certs(
            processed_cert, cert_candidate_id
        ):
            return False

        if self.algorithms is None:
            raise RuntimeError("Dataset was probably not built correctly - this should not be happening.")

        if not FIPSDataset._match_with_algorithm(processed_cert, cert_candidate_id):
            return False

        algs = self.algorithms.certs_for_id(cert_candidate_id)
        for current_alg in algs:
            if current_alg.vendor is None or processed_cert.web_data.vendor is None:
                raise RuntimeError("Dataset was probably not built correctly - this should not be happening.")

            if FIPSCertificate.get_compare(processed_cert.web_data.vendor) == FIPSCertificate.get_compare(
                current_alg.vendor
            ):
                return False
        return True

    def _compute_dependencies(self) -> None:
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

    def _analyze_certificates_body(self, fresh: bool = True) -> None:
        super()._analyze_certificates_body(fresh)

        # Final methods -- delete them, just a placeholder, they're handled by superclass
        # self._extract_data()
        # self._compute_heuristics()

        # TODO: Distribute the methods below somehow between the final methods above
        self._extract_data(redo=False)
        self.extract_certs_from_tables(high_precision=True)
        self._extract_metadata()
        self._unify_algorithms()
        self._compute_heuristics_clean_ids()
        self._compute_dependencies()
        self.compute_cpe_heuristics()
        self.compute_related_cves()
        self.plot_graphs(show=True)

    def _compute_heuristics(self):
        logger.info("Computing various statistics from processed certificates.")

    def _highlight_vendor_in_dot(self, dot: Digraph, current_dgst: str, highlighted_vendor: str) -> None:
        current_cert = self.certs[current_dgst]

        if current_cert.web_data.vendor != highlighted_vendor:
            return

        dot.attr("node", color="red")
        if current_cert.web_data.status == "Revoked":
            dot.attr("node", color="grey32")
        if current_cert.web_data.status == "Historical":
            dot.attr("node", color="gold3")

    def _add_colored_node(self, dot: Digraph, current_dgst: str, highlighted_vendor: str) -> None:
        current_cert = self.certs[current_dgst]
        dot.attr("node", color="lightgreen")
        if current_cert.web_data.status == "Revoked":
            dot.attr("node", color="lightgrey")
        if current_cert.web_data.status == "Historical":
            dot.attr("node", color="gold")
        self._highlight_vendor_in_dot(dot, current_dgst, highlighted_vendor)
        dot.node(
            str(current_cert.cert_id),
            label=str(current_cert.cert_id) + "&#10;" + current_cert.web_data.vendor
            if current_cert.web_data.vendor is not None
            else "" + "&#10;" + (current_cert.web_data.module_name if current_cert.web_data.module_name else ""),
        )

    def _get_processed_list(self, connection_list: str, dgst: str) -> List[str]:
        attr = {"st": "st_references", "web": "web_references"}[connection_list]
        return getattr(self.certs[dgst].heuristics, attr).directly_referencing

    def _create_dot_graph(
        self,
        output_file_name: str,
        connection_list: str = "st",
        highlighted_vendor: str = "Red Hat®, Inc.",
        show: bool = True,
    ) -> None:
        """
        Function that plots .dot graph of dependencies between certificates
        Certificates with at least one dependency are displayed in "{output_file_name}connections.pdf", remaining
        certificates are displayed in {output_file_name}single.pdf
        :param show: display graph right on screen
        :param highlighted_vendor: vendor whose certificates should be highlighted in red color
        :param output_file_name: prefix to "connections", "connections.pdf", "single" and "single.pdf"
        :param connection_list: 'st' or 'web' - plots a graph from this source
        """
        dot = Digraph(comment="Certificate ecosystem")
        single_dot = Digraph(comment="Modules with no dependencies")
        single_dot.attr("graph", label="Single nodes", labelloc="t", fontsize="30")
        single_dot.attr("node", style="filled")
        dot.attr("graph", label="Dependencies", labelloc="t", fontsize="30")
        dot.attr("node", style="filled")

        keys = 0
        edges = 0

        for key in self.certs:
            cert = self.certs[key]

            # TODO: Not sure what this was for, fix me
            # if not cert.state.file_status:
            #     continue

            processed = self._get_processed_list(connection_list, key)

            if processed:
                self._add_colored_node(dot, key, highlighted_vendor)
                keys += 1
            else:
                single_dot.attr("node", color="lightblue")
                self._highlight_vendor_in_dot(dot, key, highlighted_vendor)
                single_dot.node(
                    key,
                    label=str(cert.cert_id) + "\r\n" + cert.web_data.vendor
                    if cert.web_data.vendor is not None
                    else "" + ("\r\n" + cert.web_data.module_name if cert.web_data.module_name else ""),
                )

        for key in self.certs:
            cert = self.certs[key]

            # TODO: Not sure what this was for, fix me
            # if not cert.state.file_status:
            #     continue

            processed = self._get_processed_list(connection_list, key)
            for conn in processed:
                self._add_colored_node(dot, fips_dgst(conn), highlighted_vendor)
                dot.edge(key, conn)
                edges += 1

        logger.info(f"rendering for {connection_list}: {keys} keys and {edges} edges")

        dot.render(self.root_dir / (str(output_file_name) + "_connections"), view=show)
        single_dot.render(self.root_dir / (str(output_file_name) + "_single"), view=show)

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

    def plot_graphs(self, show: bool = False) -> None:
        """
        Plots FIPS graphs.

        :param bool show: If plots should be shown with .show() method, defaults to False
        """
        self._create_dot_graph("full_graph", show=show)
        self._create_dot_graph("web_only_graph", "web", show=show)
        self._create_dot_graph("st_only_graph", "st", show=show)
