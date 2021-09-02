import tempfile
import logging
import os
from itertools import groupby
from pathlib import Path
from typing import ClassVar, Tuple, List, Dict, Optional, Union

from bs4 import BeautifulSoup
from graphviz import Digraph

from sec_certs import constants as constants, parallel_processing as cert_processing, helpers as helpers
from sec_certs.configuration import config
from sec_certs.dataset.dataset import Dataset, logger
from sec_certs.dataset.fips_algorithm import FIPSAlgorithmDataset
from sec_certs.serialization import ComplexSerializableType, serialize
from sec_certs.certificate.fips import FIPSCertificate
from sec_certs.dataset.cpe import CPEDataset


class FIPSDataset(Dataset, ComplexSerializableType):
    certs: Dict[str, FIPSCertificate]

    def __init__(
        self, certs: dict, root_dir: Path, name: str = "dataset name", description: str = "dataset_description"
    ):
        super().__init__(certs, root_dir, name, description)
        self.keywords = {}
        self.algorithms = None
        self.new_files = 0

    @property
    def web_dir(self) -> Path:
        return self.root_dir / "web"

    @property
    def results_dir(self) -> Path:
        return self.root_dir / "results"

    @property
    def policies_dir(self) -> Path:
        return self.root_dir / "security_policies"

    @property
    def fragments_dir(self) -> Path:
        return self.root_dir / "fragments"

    @property
    def algs_dir(self) -> Path:
        return self.web_dir / "algorithms"

    @property
    def auxillary_datasets_dir(self) -> Path:
        return self.root_dir / 'auxillary_datasets'

    # After web scan, there should be a FIPSCertificate object created for every entry
    @property
    def successful_web_scan(self) -> bool:
        return all(self.certs) and all(cert.web_scan for cert in self.certs.values())

    @property
    def successful_pdf_scan(self) -> bool:
        return all(cert.pdf_scan for cert in self.certs.values())

    @property
    def json_path(self) -> Path:
        return self.root_dir / (self.name + '.json')

    def find_empty_pdfs(self) -> Tuple[List, List]:
        missing = []
        not_available = []
        for i in self.certs:
            if not (self.policies_dir / f"{i}.pdf").exists():
                missing.append(i)
            elif os.path.getsize(self.policies_dir / f"{i}.pdf") < constants.FIPS_NOT_AVAILABLE_CERT_SIZE:
                not_available.append(i)
        return missing, not_available

    @serialize
    def pdf_scan(self, redo=False):
        logger.info("Entering PDF scan.")

        self.fragments_dir.mkdir(parents=True, exist_ok=True)

        keywords = cert_processing.process_parallel(
            FIPSCertificate.find_keywords,
            [cert for cert in self.certs.values() if not cert.pdf_scan.keywords or redo],
            config.n_threads,
            use_threading=False,
        )
        for keyword, cert in keywords:
            self.certs[cert.dgst].pdf_scan.keywords = keyword

    def match_algs(self) -> Dict:
        output = {}
        cert: FIPSCertificate
        for cert in self.certs.values():
            # if the pdf has not been processed, no matching can be done
            if not cert.pdf_scan.keywords or not cert.state.txt_state:
                continue
            
            output[cert.dgst] = FIPSCertificate.match_web_algs_to_pdf(cert)
            cert.processed.unmatched_algs = output[cert.dgst]

        output = {k: v for k, v in output.items() if v != 0}
        return output

    def download_all_pdfs(self):
        sp_paths, sp_urls = [], []
        self.policies_dir.mkdir(exist_ok=True)

        for cert_id in list(self.certs.keys()):
            if not (self.policies_dir / f"{cert_id}.pdf").exists() or (
                self.certs[cert_id] and not self.certs[cert_id].state.txt_state
            ):
                sp_urls.append(
                    f"https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp{cert_id}.pdf"
                )
                sp_paths.append(self.policies_dir / f"{cert_id}.pdf")
        logging.info(f"downloading {len(sp_urls)} module pdf files")
        cert_processing.process_parallel(
            FIPSCertificate.download_security_policy, list(zip(sp_urls, sp_paths)), config.n_threads
        )
        self.new_files += len(sp_urls)

    def download_all_htmls(self) -> List[str]:
        html_paths, html_urls = [], []
        new_files = []
        self.web_dir.mkdir(exist_ok=True)
        for cert_id in self.certs.keys():
            if not (self.web_dir / f"{cert_id}.html").exists():
                html_urls.append(
                    f"https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/{cert_id}"
                )
                html_paths.append(self.web_dir / f"{cert_id}.html")
                new_files.append(cert_id)

        logging.info(f"downloading {len(html_urls)} module html files")
        failed = cert_processing.process_parallel(
            FIPSCertificate.download_html_page, list(zip(html_urls, html_paths)), config.n_threads
        )
        failed = [c for c in failed if c]

        self.new_files += len(html_urls)
        logging.info(f"Download failed for {len(failed)} files. Retrying...")
        cert_processing.process_parallel(FIPSCertificate.download_html_page, failed, config.n_threads)
        return new_files

    @serialize
    def convert_all_pdfs(self):
        logger.info('Converting FIPS certificate reports to .txt')
        tuples = [
            (cert, self.policies_dir / f"{cert.cert_id}.pdf", self.policies_dir / f"{cert.cert_id}.pdf.txt")
            for cert in self.certs.values()
            if not cert.state.txt_state and (self.policies_dir / f"{cert.cert_id}.pdf").exists()
        ]
        cert_processing.process_parallel(FIPSCertificate.convert_pdf_file, tuples, config.n_threads)

    def prepare_dataset(self, test: Optional[Path] = None, update: bool = False):
        if test:
            html_files = [test]
        else:
            html_files = ["fips_modules_active.html", "fips_modules_historical.html", "fips_modules_revoked.html"]
            helpers.download_file(
                "https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&CertificateStatus=Active&ValidationYear=0",
                self.web_dir / "fips_modules_active.html",
            )
            helpers.download_file(
                "https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&CertificateStatus=Historical&ValidationYear=0",
                self.web_dir / "fips_modules_historical.html",
            )
            helpers.download_file(
                "https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&CertificateStatus=Revoked&ValidationYear=0",
                self.web_dir / "fips_modules_revoked.html",
            )

        # Parse those files and get list of currently processable files (always)
        for f in html_files:
            self._get_certificates_from_html(self.web_dir / f, update)

    def download_neccessary_files(self):
        self.download_all_htmls()
        self.download_all_pdfs()

    def _get_certificates_from_html(self, html_file: Path, update: bool = False) -> None:
        logger.info(f"Getting certificate ids from {html_file}")
        with open(html_file, "r", encoding="utf-8") as handle:
            html = BeautifulSoup(handle.read(), "html.parser")

        table = [x for x in html.find(id="searchResultsTable").tbody.contents if x != "\n"]
        for entry in table:
            cert_id = entry.find("a").text
            if cert_id not in self.certs:
                self.certs[cert_id] = None

    @serialize
    def web_scan(self, redo: bool = False):
        logger.info("Entering web scan.")
        for cert_id, cert in self.certs.items():
            self.certs[cert_id] = FIPSCertificate.html_from_file(
                self.web_dir / f"{cert_id}.html",
                FIPSCertificate.State(
                    (self.policies_dir / cert_id).with_suffix(".pdf"),
                    (self.web_dir / cert_id).with_suffix(".html"),
                    (self.fragments_dir / cert_id).with_suffix(".txt"),
                    False,
                    None,
                    False,
                ),
                cert,
                redo=redo,
            )

    @classmethod
    def from_web_latest(cls):
        with tempfile.TemporaryDirectory() as tmp_dir:
            dset_path = Path(tmp_dir) / 'fips_latest_dataset.json'
            logger.info('Downloading the latest FIPS dataset.')
            helpers.download_file(config.fips_latest_snapshot, dset_path)
            dset: FIPSDataset = cls.from_json(dset_path)
            logger.info('The dataset with %s certs and %s algorithms.', len(dset), len(dset.algorithms))
            logger.info('The dataset does not contain the results of the dependency analysis - calculating them now...')
            dset.finalize_results()
            return dset

    @classmethod
    def from_json(cls, input_path: Union[str, Path]):
        dset = super().from_json(input_path)
        dset.set_local_paths()
        return dset

    def set_local_paths(self):
        cert: FIPSCertificate
        for cert in self.certs:
            cert.set_local_paths(self.policies_dir, self.web_dir, self.fragments_dir)

    def _append_new_certs_data(self) -> int:
        # we need to know the exact certificates downloaded, so we don't overwrite something already done
        new_certs = self.download_all_htmls()
        self.download_all_pdfs()
        logger.info(f"{self.new_files} needed to be downloaded")
        for cert_id in new_certs:
            self.certs[cert_id] = None
        return len(new_certs)

    @serialize
    def get_certs_from_web(
        self,
        test: Optional[Path] = None,
        no_download_algorithms: bool = False,
        update: bool = False,
    ):
        logger.info("Downloading required html files")

        self.web_dir.mkdir(parents=True, exist_ok=True)
        self.policies_dir.mkdir(exist_ok=True)
        self.algs_dir.mkdir(exist_ok=True)

        # Download files containing all available module certs (always)
        self.prepare_dataset(test, update)

        logger.info("Downloading certificate html and security policies")
        self.download_neccessary_files()

        if not no_download_algorithms:
            aset = FIPSAlgorithmDataset({}, Path(self.root_dir / 'web' / 'algorithms'), 'algorithms', 'sample algs')
            aset.get_certs_from_web()
            logging.info(f'Finished parsing. Have algorithm dataset with {len(aset)} algorithm numbers.')

            self.algorithms = aset

    @serialize
    def deprocess(self):
        #TODO
        logger.info("Removing 'processed' field. This dataset can be used to be uploaded and later downloaded using latest_snapshot() or something")
        cert: FIPSCertificate
        for cert in self.certs.values():
            cert.processed = FIPSCertificate.Processed(None, {}, [], 0)

        self.match_algs()


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
                if (not cert.state.tables_done or high_precision) and cert.state.txt_state
            ],
            config.n_threads // 4,  # tabula already processes by parallel, so
            # it's counterproductive to use all threads
            use_threading=False,
        )

        not_decoded = [cert.state.sp_path for done, cert, _ in result if done is False]
        for state, cert, algorithms in result:
            self.certs[cert.dgst].state.tables_done = state
            self.certs[cert.dgst].pdf_scan.algorithms += algorithms
        return not_decoded

    def remove_algorithms_from_extracted_data(self):
        for cert in self.certs.values():
            cert.remove_algorithms()

    def unify_algorithms(self):
        certificate: FIPSCertificate
        for certificate in self.certs.values():
            new_algorithms: List[Dict] = []
            united_algorithms = [
                x
                for x in (certificate.web_scan.algorithms + certificate.pdf_scan.algorithms)
                if x != {"Certificate": []}
            ]
            for algorithm in united_algorithms:
                if isinstance(algorithm, dict):
                    new_algorithms.append(algorithm)
                else:
                    new_algorithms.append({"Certificate": [algorithm]})
            certificate.processed.algorithms = new_algorithms

            # returns True if candidates should _not_ be matched

    def _compare_certs(self, current_certificate: "FIPSCertificate", other_id: str):
        cert_first = current_certificate.web_scan.date_validation[0].year
        cert_last = current_certificate.web_scan.date_validation[-1].year
        conn_first = self.certs[other_id].web_scan.date_validation[0].year
        conn_last = self.certs[other_id].web_scan.date_validation[-1].year

        return (
            cert_first - conn_first > config.year_difference_between_validations
            and cert_last - conn_last > config.year_difference_between_validations
            or cert_first < conn_first
        )

    def _remove_false_positives_for_cert(self, current_cert: FIPSCertificate):
        for rule in current_cert.processed.keywords["rules_cert_id"]:
            matches = current_cert.processed.keywords["rules_cert_id"][rule]
            current_cert.processed.keywords["rules_cert_id"][rule] = [
                cert_id
                for cert_id in matches
                if self._validate_id(current_cert, cert_id.replace("Cert.", "").replace("cert.", "").lstrip("#CA0 "))
                and cert_id != current_cert.cert_id
            ]

    def _validate_id(self, processed_cert: FIPSCertificate, cert_candidate: str) -> bool:
        if cert_candidate not in self.certs or not cert_candidate.isdecimal():
            return False

        # "< number" still needs to be used, because of some old certs being revalidated
        if int(cert_candidate) < config.smallest_certificate_id_to_connect or self._compare_certs(
            processed_cert, cert_candidate
        ):
            return False
        if cert_candidate not in self.algorithms.certs:
            return True

        for cert_alg in processed_cert.processed.algorithms:
            for certificate in cert_alg["Certificate"]:
                curr_id = "".join(filter(str.isdigit, certificate))
                if curr_id == cert_candidate:
                    return False

        algs = self.algorithms.certs[cert_candidate]
        for current_alg in algs:
            if FIPSCertificate.get_compare(processed_cert.web_scan.vendor) == FIPSCertificate.get_compare(
                current_alg.vendor
            ):
                return False
        return True

    @staticmethod
    def _find_connections(current_cert: FIPSCertificate):
        current_cert.processed.connections = []
        current_cert.web_scan.connections = []
        current_cert.pdf_scan.connections = []
        if not current_cert.state.file_status or not current_cert.processed.keywords:
            return
        if current_cert.processed.keywords["rules_cert_id"] == {}:
            return
        for rule in current_cert.processed.keywords["rules_cert_id"]:
            for cert in current_cert.processed.keywords["rules_cert_id"][rule]:
                cert_id = "".join(filter(str.isdigit, cert))
                if cert_id not in current_cert.processed.connections:
                    current_cert.processed.connections.append(cert_id)
                    current_cert.pdf_scan.connections.append(cert_id)

        # We want connections parsed in caveat to bypass age check, because we are 100 % sure they are right
        if current_cert.web_scan.mentioned_certs:
            for item in current_cert.web_scan.mentioned_certs:
                cert_id = "".join(filter(str.isdigit, item))
                if cert_id not in current_cert.processed.connections and cert_id != "":
                    current_cert.processed.connections.append(cert_id)
                    current_cert.web_scan.connections.append(cert_id)

    @serialize
    def compute_cpe_heuristics(self):
        """
        Computes stuff related to CPE matching
        """
        self._compute_candidate_versions()
        self._compute_cpe_matches()

    def _prepare_cpe_dataset(self, download_fresh_cpes):
        logger.info('Preparing CPE dataset.')
        if not self.auxillary_datasets_dir.exists():
            self.auxillary_datasets_dir.mkdir(parents=True)

        if not self.cpe_dataset_path.exists() or download_fresh_cpes is True:
            cpe_dataset = CPEDataset.from_web()
            cpe_dataset.to_json(str(self.cpe_dataset_path))
        else:
            cpe_dataset = CPEDataset.from_json(str(self.cpe_dataset_path))

        return cpe_dataset

    def _compute_candidate_versions(self):
        logger.info('Computing heuristics: possible product versions in certificate name')
        for cert in self:
            cert.compute_heuristics_version()

    def _compute_cpe_matches(self, download_fresh_cpes: bool = False):
        logger.info('Computing heuristics: Finding CPE matches for certificates')
        cpe_dset = self.prepare_cpe_dataset(download_fresh_cpes)

        for cert in self:
            cert.compute_heuristics_cpe_match(cpe_dset)

    def validate_results(self):
        """
        Function that validates results and finds the final connection output
        """
        current_cert: FIPSCertificate

        for current_cert in self.certs.values():
            if not current_cert.state.txt_state:
                continue
            self._remove_false_positives_for_cert(current_cert)

        for current_cert in self.certs.values():
            FIPSDataset._find_connections(current_cert)

    @serialize
    def finalize_results(self):
        logger.info("Entering 'analysis' and building connections between certificates.")
        self.unify_algorithms()
        self.remove_algorithms_from_extracted_data()
        self.validate_results()

    def _highlight_vendor_in_dot(self, dot: Digraph, current_key: str, highlighted_vendor: str):
        if self.certs[current_key].web_scan.vendor != highlighted_vendor:
            return

        dot.attr("node", color="red")
        if self.certs[current_key].web_scan.status == "Revoked":
            dot.attr("node", color="grey32")
        if self.certs[current_key].web_scan.status == "Historical":
            dot.attr("node", color="gold3")

    def _add_colored_node(self, dot: Digraph, current_key: str, highlighted_vendor: str):
        dot.attr("node", color="lightgreen")
        if self.certs[current_key].web_scan.status == "Revoked":
            dot.attr("node", color="lightgrey")
        if self.certs[current_key].web_scan.status == "Historical":
            dot.attr("node", color="gold")
        self._highlight_vendor_in_dot(dot, current_key, highlighted_vendor)
        dot.node(
            current_key,
            label=current_key
            + "&#10;"
            + self.certs[current_key].web_scan.vendor
            + "&#10;"
            + (self.certs[current_key].web_scan.module_name if self.certs[current_key].web_scan.module_name else ""),
        )

    def _get_processed_list(self, connection_list: str, key: str):
        attr = {"pdf": "pdf_scan", "web": "web_scan", "processed": "processed"}[connection_list]
        return getattr(self.certs[key], attr).connections

    def get_dot_graph(
        self,
        output_file_name: str,
        connection_list: str = "processed",
        highlighted_vendor: str = "Red Hat®, Inc.",
        show: bool = True,
    ):
        """
        Function that plots .dot graph of dependencies between certificates
        Certificates with at least one dependency are displayed in "{output_file_name}connections.pdf", remaining
        certificates are displayed in {output_file_name}single.pdf
        :param show: display graph right on screen
        :param highlighted_vendor: vendor whose certificates should be highlighted in red color
        :param output_file_name: prefix to "connections", "connections.pdf", "single" and "single.pdf"
        :param connection_list: 'processed', 'web', or 'pdf' - plots a graph from this source
                                default - processed
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
            if key == "Not found" or not self.certs[key].state.file_status:
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
                    label=key
                    + "\r\n"
                    + self.certs[key].web_scan.vendor
                    + ("\r\n" + self.certs[key].web_scan.module_name if self.certs[key].web_scan.module_name else ""),
                )

        for key in self.certs:
            if key == "Not found" or not self.certs[key].state.file_status:
                continue
            processed = self._get_processed_list(connection_list, key)
            for conn in processed:
                self._add_colored_node(dot, conn, highlighted_vendor)
                dot.edge(key, conn)
                edges += 1

        logging.info(f"rendering for {connection_list}: {keys} keys and {edges} edges")

        dot.render(self.root_dir / (str(output_file_name) + "_connections"), view=show)
        single_dot.render(self.root_dir / (str(output_file_name) + "_single"), view=show)

    def to_dict(self):
        return {'timestamp': self.timestamp, 'sha256_digest': self.sha256_digest,
                'name': self.name, 'description': self.description,
            'n_certs': len(self), 'certs': self.certs, 'algs': self.algorithms}

    @classmethod
    def from_dict(cls, dct: Dict):
        certs = dct["certs"]
        dset = cls(certs, Path("./"), dct["name"], dct["description"])
        dset.algorithms = dct["algs"]
        if len(dset) != (claimed := dct["n_certs"]):
            logger.error(
                f"The actual number of certs in dataset ({len(dset)}) does not match the claimed number ({claimed})."
            )
        return dset

    def group_vendors(self) -> Dict:
        vendors = {}
        v = {x.web_scan.vendor.lower() for x in self.certs.values()}
        v = sorted(v, key=FIPSCertificate.get_compare)
        for prefix, a in groupby(v, key=FIPSCertificate.get_compare):
            vendors[prefix] = list(a)

        return vendors

    def plot_graphs(self, show: bool = False):
        self.get_dot_graph("full_graph", show=show)
        self.get_dot_graph("web_only_graph", "web", show=show)
        self.get_dot_graph("pdf_only_graph", "pdf", show=show)
