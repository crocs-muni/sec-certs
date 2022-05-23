import logging
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from bs4 import BeautifulSoup, NavigableString
from graphviz import Digraph

from sec_certs import helpers as helpers
from sec_certs import parallel_processing as cert_processing
from sec_certs.config.configuration import config
from sec_certs.dataset.dataset import Dataset
from sec_certs.dataset.fips_algorithm import FIPSAlgorithmDataset
from sec_certs.helpers import fips_dgst
from sec_certs.model.dependency_finder import DependencyFinder
from sec_certs.sample.fips import FIPSCertificate
from sec_certs.serialization.json import ComplexSerializableType, serialize

logger = logging.getLogger(__name__)


class FIPSDataset(Dataset[FIPSCertificate], ComplexSerializableType):
    """
    Class for processing of FIPSCertificate samples. Inherits from `ComplexSerializableType` and base abstract `Dataset` class.
    """

    def __init__(
        self,
        certs: Dict[str, FIPSCertificate] = dict(),
        root_dir: Optional[Path] = None,
        name: str = "FIPS Dataset",
        description: str = "No description",
    ):
        super().__init__(certs, root_dir, name, description)
        self.keywords: Dict[str, Dict] = {}
        self.algorithms: Optional[FIPSAlgorithmDataset] = None
        self.new_files = 0

    @property
    def _policies_dir(self) -> Path:
        return self.root_dir / "security_policies"

    @property
    def _fragments_dir(self) -> Path:
        return self.root_dir / "fragments"

    @property
    def _algs_dir(self) -> Path:
        return self.web_dir / "algorithms"

    def _get_certs_from_name(self, module_name: str) -> List[FIPSCertificate]:
        """
        Returns list of certificates that match given name.

        :param str module_name: name to search for
        :return List[FIPSCertificate]: List of certificates with web_scan.module_name == module_name
        """
        return [crt for crt in self if crt.web_scan.module_name == module_name]

    @serialize
    def pdf_scan(self, redo: bool = False) -> None:
        """
        pdf_scan()
        Extracts data from pdf files

        :param bool redo: Whether to try again with failed files, defaults to False
        """
        logger.info("Entering PDF scan.")

        self._fragments_dir.mkdir(parents=True, exist_ok=True)

        keywords = cert_processing.process_parallel(
            FIPSCertificate.find_keywords,
            [cert for cert in self.certs.values() if not cert.pdf_scan.keywords or redo],
            config.n_threads,
            use_threading=False,
            progress_bar_desc="Scanning PDF files",
        )
        for keyword, cert in keywords:
            self.certs[cert.dgst].pdf_scan.keywords = keyword

    def _match_algs(self) -> Dict[str, int]:
        output = {}
        for cert in self.certs.values():
            # if the pdf has not been processed, no matching can be done
            if not cert.pdf_scan.keywords or not cert.state.txt_state:
                continue

            output[cert.dgst] = FIPSCertificate.match_web_algs_to_pdf(cert)
            cert.heuristics.unmatched_algs = output[cert.dgst]

        output = {k: v for k, v in output.items() if v != 0}
        return output

    def download_all_pdfs(self, cert_ids: Optional[Set[str]] = None) -> None:
        """
        Downloads all pdf files related to the certificates specified with cert_ids.

        :param Optional[Set[str]] cert_ids: cert_ids to download the pdfs foor, defaults to None
        :raises RuntimeError: If no cert_ids are specified, raises.
        """
        sp_paths, sp_urls = [], []
        self._policies_dir.mkdir(exist_ok=True)
        if cert_ids is None:
            raise RuntimeError("You need to provide cert ids to FIPS download PDFs functionality.")
        for cert_id in cert_ids:
            if not (self._policies_dir / f"{cert_id}.pdf").exists() or (
                fips_dgst(cert_id) in self.certs and not self.certs[fips_dgst(cert_id)].state.txt_state
            ):
                sp_urls.append(
                    f"https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp{cert_id}.pdf"
                )
                sp_paths.append(self._policies_dir / f"{cert_id}.pdf")
        logger.info(f"downloading {len(sp_urls)} module pdf files")
        cert_processing.process_parallel(
            FIPSCertificate.download_security_policy,
            list(zip(sp_urls, sp_paths)),
            config.n_threads,
            progress_bar_desc="Downloading PDF files",
        )
        self.new_files += len(sp_urls)

    def _download_all_htmls(self, cert_ids: Set[str]) -> List[str]:
        html_paths, html_urls = [], []
        new_files = []
        self.web_dir.mkdir(exist_ok=True)
        for cert_id in cert_ids:
            if not (self.web_dir / f"{cert_id}.html").exists():
                html_urls.append(
                    f"https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/{cert_id}"
                )
                html_paths.append(self.web_dir / f"{cert_id}.html")
                new_files.append(cert_id)

        logger.info(f"downloading {len(html_urls)} module html files")
        failed = cert_processing.process_parallel(
            FIPSCertificate.download_html_page,
            list(zip(html_urls, html_paths)),
            config.n_threads,
            progress_bar_desc="Downloading HTML files",
        )
        failed = [c for c in failed if c]

        self.new_files += len(html_urls)
        if len(failed) != 0:
            logger.info(f"Download failed for {len(failed)} files. Retrying...")
            cert_processing.process_parallel(
                FIPSCertificate.download_html_page,
                failed,
                config.n_threads,
                progress_bar_desc="Downloading HTML files again",
            )
        return new_files

    @serialize
    def convert_all_pdfs(self) -> None:
        """
        Converts all pdfs to text files
        """
        logger.info("Converting FIPS sample reports to .txt")
        tuples = [
            (cert, self._policies_dir / f"{cert.cert_id}.pdf", self._policies_dir / f"{cert.cert_id}.pdf.txt")
            for cert in self.certs.values()
            if not cert.state.txt_state and (self._policies_dir / f"{cert.cert_id}.pdf").exists()
        ]
        cert_processing.process_parallel(
            FIPSCertificate.convert_pdf_file, tuples, config.n_threads, progress_bar_desc="Converting to txt"
        )

    def _prepare_dataset(self, test: Optional[Path] = None, update: bool = False) -> Set[str]:
        if test:
            html_files = [test]
        else:
            html_files = [
                Path("fips_modules_active.html"),
                Path("fips_modules_historical.html"),
                Path("fips_modules_revoked.html"),
            ]
            helpers.download_file(
                "https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&CertificateStatus=Active&ValidationYear=0",
                Path(self.web_dir / "fips_modules_active.html"),
            )
            helpers.download_file(
                "https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&CertificateStatus=Historical&ValidationYear=0",
                Path(self.web_dir / "fips_modules_historical.html"),
            )
            helpers.download_file(
                "https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&CertificateStatus=Revoked&ValidationYear=0",
                Path(self.web_dir / "fips_modules_revoked.html"),
            )

        # Parse those files and get list of currently processable files (always)
        cert_ids: Set[str] = set()
        for f in html_files:
            cert_ids |= self._get_certificates_from_html(self.web_dir / f, update)

        return cert_ids

    def _download_neccessary_files(self, cert_ids: Set[str]) -> None:
        self._download_all_htmls(cert_ids)
        self.download_all_pdfs(cert_ids)

    def _get_certificates_from_html(self, html_file: Path, update: bool = False) -> Set[str]:
        logger.info(f"Getting certificate ids from {html_file}")
        with open(html_file, "r", encoding="utf-8") as handle:
            html = BeautifulSoup(handle.read(), "html5lib")

        table = [x for x in html.find(id="searchResultsTable").tbody.contents if x != "\n"]
        entries: Set[str] = set()

        for entry in table:
            if isinstance(entry, NavigableString):
                continue
            cert_id = entry.find("a").text
            if cert_id not in entries:
                entries.add(cert_id)

        return entries

    @serialize
    def web_scan(self, cert_ids: Set[int], redo: bool = False) -> None:
        """
        Creates FIPSCertificate object from the relevant html file that must be downlaoded.

        :param Set[int] cert_ids: Cert ids to create FIPSCertificate objects for.
        :param bool redo: whether to re-attempt with failed certificates, defaults to False
        """
        logger.info("Entering web scan.")
        for cert_id in cert_ids:
            dgst = fips_dgst(cert_id)
            self.certs[dgst] = FIPSCertificate.from_html_file(
                self.web_dir / f"{cert_id}.html",
                FIPSCertificate.State(
                    (self._policies_dir / str(cert_id)).with_suffix(".pdf"),
                    (self.web_dir / str(cert_id)).with_suffix(".html"),
                    (self._fragments_dir / str(cert_id)).with_suffix(".txt"),
                    False,
                    None,
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
        with tempfile.TemporaryDirectory() as tmp_dir:
            dset_path = Path(tmp_dir) / "fips_latest_dataset.json"
            logger.info("Downloading the latest FIPS dataset.")
            helpers.download_file(
                config.fips_latest_snapshot,
                dset_path,
                show_progress_bar=True,
                progress_bar_desc="Downloading FIPS dataset",
            )
            dset: FIPSDataset = cls.from_json(dset_path)
            logger.info(
                "The dataset with %s certs and %s algorithms.",
                len(dset),
                len(dset.algorithms) if dset.algorithms is not None else 0,
            )
            # TODO: Fixme, this is really costly
            # logger.info("The dataset does not contain the results of the dependency analysis - calculating them now...")
            # dset.finalize_results()
            return dset

    def _set_local_paths(self) -> None:
        cert: FIPSCertificate
        for cert in self.certs.values():
            cert.set_local_paths(self._policies_dir, self.web_dir, self._fragments_dir)

    @serialize
    def get_certs_from_web(
        self,
        test: Optional[Path] = None,
        no_download_algorithms: bool = False,
        update: bool = False,
        redo_web_scan=False,
    ) -> None:
        """Downloads HTML search pages, parses them, populates the dataset,
        and performs `web-scan` - extracting information from CMVP pages for
        each certificate.

        Args:
            test (Optional[Path], optional): Path to dataset used in testing. Defaults to None.
            no_download_algorithms (bool, optional): Whether to reuse CAVP algorithm dataset. Defaults to False.
            update (bool, optional): Whether to update dataset with new entries. Defaults to False.
            redo_web_scan (bool, optional): Whether to redo the `web-scan` functionality. Defaults to False.
        """
        logger.info("Downloading required html files")

        self.web_dir.mkdir(parents=True, exist_ok=True)
        self._policies_dir.mkdir(exist_ok=True)
        self._algs_dir.mkdir(exist_ok=True)

        # Download files containing all available module certs (always)
        cert_ids = self._prepare_dataset(test, update)

        if not no_download_algorithms:
            aset = FIPSAlgorithmDataset({}, Path(self.root_dir / "web" / "algorithms"), "algorithms", "sample algs")
            aset.get_certs_from_web()
            logger.info(f"Finished parsing. Have algorithm dataset with {len(aset)} algorithm numbers.")

            self.algorithms = aset

        logger.info("Downloading certificate html and security policies")
        self._download_neccessary_files(cert_ids)

        self.web_scan(cert_ids, redo=redo_web_scan)

    @serialize
    def extract_certs_from_tables(self, high_precision: bool) -> List[Path]:
        """
        Function that extracts algorithm IDs from tables in security policies files.
        :return: list of files that couldn't have been decoded
        """
        logger.info("Entering table scan.")
        result = cert_processing.process_parallel(
            FIPSCertificate.analyze_tables,
            [
                (cert, high_precision)
                for cert in self.certs.values()
                if cert is not None and (not cert.state.tables_done or high_precision) and cert.state.txt_state
            ],
            config.n_threads // 4,  # tabula already processes by parallel, so
            # it's counterproductive to use all threads
            use_threading=False,
            progress_bar_desc="Searching tables",
        )

        not_decoded = [cert.state.sp_path for done, cert, _ in result if done is False]
        for state, cert, algorithms in result:
            certificate = self.certs[cert.dgst]
            certificate.state.tables_done = state
            certificate.pdf_scan.algorithms += algorithms
        return not_decoded

    def _remove_algorithms_from_extracted_data(self) -> None:
        for cert in self.certs.values():
            cert.remove_algorithms()

    def _unify_algorithms(self) -> None:
        for certificate in self.certs.values():
            new_algorithms: List[Dict] = []
            united_algorithms = [
                x
                for x in (
                    (certificate.web_scan.algorithms if certificate.web_scan.algorithms is not None else [])
                    + certificate.pdf_scan.algorithms
                )
                if x != {"Certificate": []}
            ]
            for algorithm in united_algorithms:
                if isinstance(algorithm, dict):
                    new_algorithms.append(algorithm)
                else:
                    new_algorithms.append({"Certificate": [algorithm]})
            certificate.heuristics.algorithms = new_algorithms

            # returns True if candidates should _not_ be matched

    def _compare_certs(self, current_certificate: FIPSCertificate, other_id: str) -> bool:
        other_dgst = fips_dgst(other_id)
        other_cert = self.certs[other_dgst]

        if (
            current_certificate.web_scan.date_validation is None
            or other_cert is None
            or other_cert.web_scan.date_validation is None
        ):
            raise RuntimeError("Building of the dataset probably failed - this should not be happening.")

        cert_first = current_certificate.web_scan.date_validation[0]
        cert_last = current_certificate.web_scan.date_validation[-1]
        conn_first = other_cert.web_scan.date_validation[0]
        conn_last = other_cert.web_scan.date_validation[-1]

        return (
            cert_first.year - conn_first.year > config.year_difference_between_validations
            and cert_last.year - conn_last.year > config.year_difference_between_validations
            or cert_first.year < conn_first.year
        )

    def _remove_false_positives_for_cert(self, current_cert: FIPSCertificate) -> None:
        if current_cert.heuristics.keywords is None:
            raise RuntimeError("Dataset was probably not built correctly - this should not be happening.")
        for rule in current_cert.heuristics.keywords["rules_cert_id"]:
            matches = current_cert.heuristics.keywords["rules_cert_id"][rule]
            current_cert.heuristics.keywords["rules_cert_id"][rule] = [
                cert_id
                for cert_id in matches
                if self._validate_id(current_cert, cert_id.replace("Cert.", "").replace("cert.", "").lstrip("#CA0 "))
                and cert_id != current_cert.cert_id
            ]

    @staticmethod
    def _match_with_algorithm(processed_cert: FIPSCertificate, cert_candidate_id: str) -> bool:
        for cert_alg in processed_cert.heuristics.algorithms:
            for certificate in cert_alg["Certificate"]:
                curr_id = "".join(filter(str.isdigit, certificate))
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

        if cert_candidate_id not in self.algorithms.certs:
            return True

        if not FIPSDataset._match_with_algorithm(processed_cert, cert_candidate_id):
            return False

        algs = self.algorithms.certs[cert_candidate_id]
        for current_alg in algs:
            if current_alg.vendor is None or processed_cert.web_scan.vendor is None:
                raise RuntimeError("Dataset was probably not built correctly - this should not be happening.")

            if FIPSCertificate.get_compare(processed_cert.web_scan.vendor) == FIPSCertificate.get_compare(
                current_alg.vendor
            ):
                return False
        return True

    def _validate_results(self) -> None:
        """
        Function that validates results and finds the final connection output
        """

        def pdf_lookup(cert):
            return set(
                filter(
                    lambda x: x,
                    map(
                        lambda cid: "".join(filter(str.isdigit, cid)),
                        cert.heuristics.keywords["rules_cert_id"].values(),
                    ),
                )
            )

        def web_lookup(cert):
            return set(
                filter(lambda x: x, map(lambda cid: "".join(filter(str.isdigit, cid)), cert.web_scan.mentioned_certs))
            )

        current_cert: FIPSCertificate

        for current_cert in self.certs.values():
            if not current_cert.state.txt_state:
                continue
            self._remove_false_positives_for_cert(current_cert)

        finder = DependencyFinder()
        finder.fit(self.certs, lambda cert: cert.cert_id, pdf_lookup)  # type: ignore

        for dgst in self.certs:
            setattr(self.certs[dgst].heuristics, "st_references", finder.predict_single_cert(dgst))

        finder = DependencyFinder()
        finder.fit(self.certs, lambda cert: cert.cert_id, web_lookup)  # type: ignore

        for dgst in self.certs:
            setattr(self.certs[dgst].heuristics, "web_references", finder.predict_single_cert(dgst))

    @serialize
    def finalize_results(self, use_nist_cpe_matching_dict: bool = True, perform_cpe_heuristics: bool = True):
        """
        Performs processing of extracted data. Computes all heuristics.

        :param bool use_nist_cpe_matching_dict: If NIST CPE matching dictionary shall be used to drive computing related CVEs, defaults to True
        :param bool perform_cpe_heuristics: If CPE heuristics shall be computed, defaults to True
        """
        logger.info("Entering 'analysis' and building connections between certificates.")
        self._unify_algorithms()
        self._remove_algorithms_from_extracted_data()
        self._validate_results()
        if perform_cpe_heuristics:
            _, _, cve_dset = self.compute_cpe_heuristics()
            self.compute_related_cves(use_nist_cpe_matching_dict=use_nist_cpe_matching_dict, cve_dset=cve_dset)

    def _highlight_vendor_in_dot(self, dot: Digraph, current_dgst: str, highlighted_vendor: str) -> None:
        current_cert = self.certs[current_dgst]

        if current_cert.web_scan.vendor != highlighted_vendor:
            return

        dot.attr("node", color="red")
        if current_cert.web_scan.status == "Revoked":
            dot.attr("node", color="grey32")
        if current_cert.web_scan.status == "Historical":
            dot.attr("node", color="gold3")

    def _add_colored_node(self, dot: Digraph, current_dgst: str, highlighted_vendor: str) -> None:
        current_cert = self.certs[current_dgst]
        dot.attr("node", color="lightgreen")
        if current_cert.web_scan.status == "Revoked":
            dot.attr("node", color="lightgrey")
        if current_cert.web_scan.status == "Historical":
            dot.attr("node", color="gold")
        self._highlight_vendor_in_dot(dot, current_dgst, highlighted_vendor)
        dot.node(
            str(current_cert.cert_id),
            label=str(current_cert.cert_id) + "&#10;" + current_cert.web_scan.vendor
            if current_cert.web_scan.vendor is not None
            else "" + "&#10;" + (current_cert.web_scan.module_name if current_cert.web_scan.module_name else ""),
        )

    def _get_processed_list(self, connection_list: str, dgst: str) -> List[str]:
        attr = {"pdf": "pdf_scan", "web": "web_scan", "heuristics": "heuristics"}[connection_list]
        return getattr(self.certs[dgst], attr).connections

    def _create_dot_graph(
        self,
        output_file_name: str,
        connection_list: str = "heuristics",
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
        :param connection_list: 'heuristics', 'web', or 'pdf' - plots a graph from this source
                                default - heuristics
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

            if not cert.state.file_status:
                continue

            processed = self._get_processed_list(connection_list, key)

            if processed:
                self._add_colored_node(dot, key, highlighted_vendor)
                keys += 1
            else:
                single_dot.attr("node", color="lightblue")
                self._highlight_vendor_in_dot(dot, key, highlighted_vendor)
                single_dot.node(
                    key,
                    label=str(cert.cert_id) + "\r\n" + cert.web_scan.vendor
                    if cert.web_scan.vendor is not None
                    else "" + ("\r\n" + cert.web_scan.module_name if cert.web_scan.module_name else ""),
                )

        for key in self.certs:
            cert = self.certs[key]

            if not cert.state.file_status:
                continue
            processed = self._get_processed_list(connection_list, key)
            for conn in processed:
                self._add_colored_node(dot, fips_dgst(conn), highlighted_vendor)
                dot.edge(key, conn)
                edges += 1

        logger.info(f"rendering for {connection_list}: {keys} keys and {edges} edges")

        dot.render(self.root_dir / (str(output_file_name) + "_connections"), view=show)
        single_dot.render(self.root_dir / (str(output_file_name) + "_single"), view=show)

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializes dataset into a dictionary

        :return Dict[str, Any]: Dictionary that holds the whole dataset.
        """
        return {
            "timestamp": self.timestamp,
            "sha256_digest": self.sha256_digest,
            "name": self.name,
            "description": self.description,
            "n_certs": len(self),
            "certs": self.certs,
            "algs": self.algorithms,
        }

    @classmethod
    def from_dict(cls, dct: Dict[str, Any]) -> "FIPSDataset":
        """
        Reconstructs the original dataset from a dictionary

        :param Dict[str, Any] dct: Dictionary that holds the serialized dataset
        :return FIPSDataset: Deserialized FIPSDataset that corresponds to `dct` contents
        """
        certs = dct["certs"]
        dset = cls(certs, Path("./"), dct["name"], dct["description"])
        dset.algorithms = dct["algs"]
        if len(dset) != (claimed := dct["n_certs"]):
            logger.error(
                f"The actual number of certs in dataset ({len(dset)}) does not match the claimed number ({claimed})."
            )
        return dset

    def plot_graphs(self, show: bool = False) -> None:
        """
        Plots FIPS graphs.
        # TODO: Currently broken, see https://github.com/crocs-muni/sec-certs/issues/211
        :param bool show: If plots should be showed with .show() method, defaults to False
        """
        self._create_dot_graph("full_graph", show=show)
        self._create_dot_graph("web_only_graph", "web", show=show)
        self._create_dot_graph("pdf_only_graph", "pdf", show=show)
