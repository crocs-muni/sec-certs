import json
import logging
import os
from itertools import groupby
from pathlib import Path
from typing import ClassVar, Tuple, List, Dict, Optional, Union

from bs4 import BeautifulSoup
from graphviz import Digraph

from sec_certs import constants as constants, cert_processing as cert_processing, helpers as helpers
from sec_certs.configuration import config
from sec_certs.dataset.dataset import Dataset, logger
from sec_certs.serialization import ComplexSerializableType, CustomJSONEncoder, CustomJSONDecoder
from sec_certs.certificate.fips import FIPSCertificate


class FIPSDataset(Dataset, ComplexSerializableType):
    FIPS_BASE_URL: ClassVar[str] = 'https://csrc.nist.gov'
    FIPS_MODULE_URL: ClassVar[
        str] = 'https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/'

    def __init__(self, certs: dict, root_dir: Path, name: str = 'dataset name',
                 description: str = 'dataset_description'):
        super().__init__(certs, root_dir, name, description)
        self.keywords = {}
        self.algorithms = None
        self.new_files = 0

    @property
    def web_dir(self) -> Path:
        return self.root_dir / 'web'

    @property
    def results_dir(self) -> Path:
        return self.root_dir / 'results'

    @property
    def policies_dir(self) -> Path:
        return self.root_dir / 'security_policies'

    @property
    def fragments_dir(self) -> Path:
        return self.root_dir / 'fragments'

    @property
    def algs_dir(self) -> Path:
        return self.web_dir / 'algorithms'

    def find_empty_pdfs(self) -> Tuple[List, List]:
        missing = []
        not_available = []
        for i in self.certs:
            if not (self.policies_dir / f'{i}.pdf').exists():
                missing.append(i)
            elif os.path.getsize(self.policies_dir / f'{i}.pdf') < constants.FIPS_NOT_AVAILABLE_CERT_SIZE:
                not_available.append(i)
        return missing, not_available

    def extract_keywords(self, redo=False):
        self.fragments_dir.mkdir(parents=True, exist_ok=True)

        keywords = cert_processing.process_parallel(FIPSCertificate.find_keywords,
                                                    [cert for cert in self.certs.values() if
                                                     not cert.pdf_scan.keywords or redo],
                                                    config.n_threads,
                                                    use_threading=False)
        for keyword, cert in keywords:
            self.certs[cert.dgst].pdf_scan.keywords = keyword

    def match_algs(self, show_graph=False) -> Dict:
        output = {}
        for cert in self.certs.values():
            output[cert.dgst] = FIPSCertificate.match_web_algs_to_pdf(cert)

        return output


    def download_all_pdfs(self):
        sp_paths, sp_urls = [], []
        self.policies_dir.mkdir(exist_ok=True)

        for cert_id in list(self.certs.keys()):
            if not (self.policies_dir / f'{cert_id}.pdf').exists() or not self.certs[cert_id].state.txt_state:
                sp_urls.append(
                    f"https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp{cert_id}.pdf")
                sp_paths.append(self.policies_dir / f"{cert_id}.pdf")
        logging.info(f"downloading {len(sp_urls)} module pdf files")
        cert_processing.process_parallel(FIPSCertificate.download_security_policy, list(zip(sp_urls, sp_paths)),
                                         config.n_threads)
        self.new_files += len(sp_urls)

    def download_all_htmls(self) -> List[str]:
        html_paths, html_urls = [], []
        new_files = []
        self.web_dir.mkdir(exist_ok=True)
        for cert_id in self.certs.keys():
            if not (self.web_dir / f'{cert_id}.html').exists():
                html_urls.append(
                    f"https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/{cert_id}")
                html_paths.append(self.web_dir / f"{cert_id}.html")
                new_files.append(cert_id)

        logging.info(f"downloading {len(html_urls)} module html files")
        failed = cert_processing.process_parallel(FIPSCertificate.download_html_page, list(zip(html_urls, html_paths)),
                                         config.n_threads)
        failed = [c for c in failed if c]

        self.new_files += len(html_urls)
        logging.info(f"Download failed for {len(failed)} files. Retrying...")
        cert_processing.process_parallel(FIPSCertificate.download_html_page, failed,
                                         config.n_threads)
        return new_files

    def convert_all_pdfs(self):
        logger.info('Converting FIPS certificate reports to .txt')
        tuples = [
            (cert, self.policies_dir / f'{cert.cert_id}.pdf', self.policies_dir / f'{cert.cert_id}.pdf.txt')
            for cert in self.certs.values() if
            not cert.state.txt_state and (self.policies_dir / f'{cert.cert_id}.pdf').exists()
        ]
        cert_processing.process_parallel(FIPSCertificate.convert_pdf_file, tuples, config.n_threads)

    def get_certs_from_web(self, redo: bool = False, json_file: Optional[Path] = None):
        def download_html_pages() -> List[str]:
            new_files = self.download_all_htmls()
            self.download_all_pdfs()
            return new_files

        def get_certificates_from_html(html_file: Path) -> None:
            logger.info(f'Getting certificate ids from {html_file}')
            with open(html_file, 'r', encoding='utf-8') as handle:
                html = BeautifulSoup(handle.read(), 'html.parser')

            table = [x for x in html.find(
                id='searchResultsTable').tbody.contents if x != '\n']
            for entry in table:
                self.certs[entry.find('a').text] = {}

        logger.info("Downloading required html files")

        self.web_dir.mkdir(parents=True, exist_ok=True)
        self.policies_dir.mkdir(exist_ok=True)
        self.algs_dir.mkdir(exist_ok=True)

        # Download files containing all available module certs (always)
        html_files = ['fips_modules_active.html',
                      'fips_modules_historical.html', 'fips_modules_revoked.html']
        helpers.download_file(
            "https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&CertificateStatus=Active&ValidationYear=0",
            self.web_dir / "fips_modules_active.html")
        helpers.download_file(
            "https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&CertificateStatus=Historical&ValidationYear=0",
            self.web_dir / "fips_modules_historical.html")
        helpers.download_file(
            "https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&CertificateStatus=Revoked&ValidationYear=0",
            self.web_dir / "fips_modules_revoked.html")

        # Parse those files and get list of currently processable files (always)
        for f in html_files:
            get_certificates_from_html(self.web_dir / f)

        logger.info('Downloading certificate html and security policies')

        if not json_file:
            json_file = self.root_dir / 'fips_full_dataset.json'

        if json_file.exists():
            logger.info("Certs loaded from previous scanning")
            dataset = self.from_json(json_file)
            self.certs = dataset.certs
            self.algorithms = dataset.algorithms

        new_certs = download_html_pages()

        logger.info(f"{self.new_files} needed to be downloaded")

        for cert_id in new_certs:
            self.certs[cert_id] = None

        if not redo and self.new_files == 0:
            logger.info('No new changes to web_scan are going to be made')
            return
        # now we want to do redo, because we want to avoid duplicites
        redo = True
        logger.info(f'Parsing web pages{" from scratch" if redo else ""}...')
        for cert_id, cert in self.certs.items():
            self.certs[cert_id] = FIPSCertificate.html_from_file(
                self.web_dir / f'{cert_id}.html',
                FIPSCertificate.State((self.policies_dir / cert_id).with_suffix('.pdf'),
                                      (self.web_dir / cert_id).with_suffix('.html'),
                                      (self.fragments_dir / cert_id).with_suffix('.txt'), False, None, False),
                cert, redo=redo)

    def extract_certs_from_tables(self) -> List[Path]:
        """
        Function that extracts algorithm IDs from tables in security policies files.
        :return: list of files that couldn't have been decoded
        """
        result = cert_processing.process_parallel(FIPSCertificate.analyze_tables,
                                                  [cert for cert in self.certs.values() if
                                                   not cert.state.tables_done and cert.state.txt_state],
                                                  config.n_threads // 4,  # tabula already processes by parallel, so
                                                  # it's counterproductive to use all threads
                                                  use_threading=False)

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
            new_algorithms = []
            united_algorithms = [x for x in (certificate.web_scan.algorithms + certificate.pdf_scan.algorithms) if
                                 x != {'Certificate': []}]
            for algorithm in united_algorithms:
                if isinstance(algorithm, dict):
                    new_algorithms.append(algorithm)
                else:
                    new_algorithms.append({'Certificate': [algorithm]})
            certificate.processed.algorithms = new_algorithms

    def validate_results(self):
        """
        Function that validates results and finds the final connection output
        """

        def validate_id(processed_cert: FIPSCertificate, cert_candidate: str) -> bool:

            # returns True if candidates should _not_ be matched
            def compare_certs(current_certificate: 'FIPSCertificate', other_id: str):
                cert_first = current_certificate.web_scan.date_validation[0].year
                cert_last = current_certificate.web_scan.date_validation[-1].year
                conn_first = self.certs[other_id].web_scan.date_validation[0].year
                conn_last = self.certs[other_id].web_scan.date_validation[-1].year

                return cert_first - conn_first > config.year_difference_between_validations \
                       and cert_last - conn_last > config.year_difference_between_validations \
                       or cert_first < conn_first

            # "< number" still needs to be used, because of some old certs being revalidated
            if cert_candidate.isdecimal() \
                    and int(cert_candidate) < config.smallest_certificate_id_to_connect or \
                    compare_certs(processed_cert, cert_candidate):
                return False
            if cert_candidate not in self.algorithms.certs:
                return True

            for cert_alg in processed_cert.processed.algorithms:
                for certificate in cert_alg['Certificate']:
                    curr_id = ''.join(filter(str.isdigit, certificate))
                    if curr_id == cert_candidate:
                        return False

            algs = self.algorithms.certs[cert_candidate]
            for current_alg in algs:
                if FIPSCertificate.get_compare(processed_cert.web_scan.vendor) == FIPSCertificate.get_compare(
                        current_alg.vendor):
                    return False
            return True

        broken_files = set()

        current_cert: FIPSCertificate

        for current_cert in self.certs.values():
            if not current_cert.state.txt_state:
                continue
            for rule in current_cert.processed.keywords['rules_cert_id']:
                for cert in current_cert.processed.keywords['rules_cert_id'][rule]:
                    cert_id = ''.join(filter(str.isdigit, cert))

                    if cert_id == '' or cert_id not in self.certs:
                        broken_files.add(current_cert.dgst)
                        current_cert.state.file_status = False
                        break

        if broken_files:
            logger.warning("CERTIFICATE FILES WITH WRONG CERTIFICATES PARSED")
            logger.warning(broken_files)
            logger.warning("... skipping these...")
            logger.warning(f"Total non-analyzable files:{len(broken_files)}")

        for current_cert in self.certs.values():
            current_cert.processed.connections = []
            if not current_cert.state.file_status or not current_cert.processed.keywords:
                continue
            if current_cert.processed.keywords['rules_cert_id'] == {}:
                continue
            for rule in current_cert.processed.keywords['rules_cert_id']:
                for cert in current_cert.processed.keywords['rules_cert_id'][rule]:
                    cert_id = ''.join(filter(str.isdigit, cert))
                    if cert_id not in current_cert.processed.connections and validate_id(current_cert, cert_id):
                        current_cert.processed.connections.append(cert_id)

    def finalize_results(self):
        self.unify_algorithms()
        self.remove_algorithms_from_extracted_data()
        self.validate_results()

    def get_dot_graph(self, output_file_name: str):
        """
        Function that plots .dot graph of dependencies between certificates
        Certificates with at least one dependency are displayed in "{output_file_name}connections.pdf", remaining
        certificates are displayed in {output_file_name}single.pdf
        :param output_file_name: prefix to "connections", "connections.pdf", "single" and "single.pdf"
        """
        dot = Digraph(comment='Certificate ecosystem')
        single_dot = Digraph(comment='Modules with no dependencies')
        single_dot.attr('graph', label='Single nodes', labelloc='t', fontsize='30')
        single_dot.attr('node', style='filled')
        dot.attr('graph', label='Dependencies', labelloc='t', fontsize='30')
        dot.attr('node', style='filled')

        def found_interesting_cert(current_key):
            if self.certs[current_key].web_scan.vendor == highlighted_vendor:
                dot.attr('node', color='red')
                if self.certs[current_key].web_scan.status == 'Revoked':
                    dot.attr('node', color='grey32')
                if self.certs[current_key].web_scan.status == 'Historical':
                    dot.attr('node', color='gold3')
            if self.certs[current_key].web_scan.vendor == "SUSE, LLC":
                dot.attr('node', color='lightblue')

        def color_check(current_key):
            dot.attr('node', color='lightgreen')
            if self.certs[current_key].web_scan.status == 'Revoked':
                dot.attr('node', color='lightgrey')
            if self.certs[current_key].web_scan.status == 'Historical':
                dot.attr('node', color='gold')
            found_interesting_cert(current_key)
            dot.node(current_key,
                     label=current_key +
                           '&#10;' +
                           self.certs[current_key].web_scan.vendor +
                           '&#10;' +
                           (self.certs[current_key].web_scan.module_name
                            if self.certs[current_key].web_scan.module_name else ''))

        keys = 0
        edges = 0

        highlighted_vendor = 'Red Hat®, Inc.'
        for key in self.certs:
            if key != 'Not found' and self.certs[key].state.file_status:
                if self.certs[key].processed.connections:
                    color_check(key)
                    keys += 1
                else:
                    single_dot.attr('node', color='lightblue')
                    found_interesting_cert(key)
                    single_dot.node(key, label=key + '\r\n' + self.certs[key].web_scan.vendor + (
                        '\r\n' + self.certs[key].web_scan.module_name if self.certs[key].web_scan.module_name else ''))

        for key in self.certs:
            if key != 'Not found' and self.certs[key].state.file_status:
                for conn in self.certs[key].processed.connections:
                    color_check(conn)
                    dot.edge(key, conn)
                    edges += 1

        logging.info(f"rendering {keys} keys and {edges} edges")

        dot.render(str(output_file_name) + '_connections', view=True)
        single_dot.render(str(output_file_name) + '_single', view=True)

    def to_dict(self):
        return {'timestamp': self.timestamp, 'sha256_digest': self.sha256_digest,
                'name': self.name, 'description': self.description,
                'n_certs': len(self), 'certs': self.certs, 'algs': self.algorithms}

    @classmethod
    def from_dict(cls, dct: Dict):
        certs = dct['certs']
        dset = cls(certs, Path('../'), dct['name'], dct['description'])
        dset.algorithms = dct['algs']
        if len(dset) != (claimed := dct['n_certs']):
            logger.error(
                f'The actual number of certs in dataset ({len(dset)}) does not match the claimed number ({claimed}).')
        return dset

    def to_json(self, output_path: Union[str, Path]):
        with Path(output_path).open('w') as handle:
            json.dump(self, handle, indent=4, cls=CustomJSONEncoder)

    @classmethod
    def from_json(cls, input_path: Union[str, Path]):
        input_path = Path(input_path)
        with input_path.open('r') as handle:
            dset = json.load(handle, cls=CustomJSONDecoder)
        dset.root_dir = input_path.parent.absolute()
        return dset

    def group_vendors(self) -> Dict:
        vendors = {}
        v = {x.vendor.lower() for x in self.certs.values()}
        v = sorted(v, key=FIPSCertificate.get_compare)
        for prefix, a in groupby(v, key=FIPSCertificate.get_compare):
            vendors[prefix] = list(a)

        return vendors