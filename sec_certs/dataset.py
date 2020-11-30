import os
import re
from datetime import datetime
import locale
import logging
from typing import Dict, List, ClassVar, Set, Tuple
import json
from importlib import import_module

import copy
from abc import ABC, abstractmethod
from pathlib import Path
import shutil

from graphviz import Digraph
from tabula import read_pdf
import pandas as pd
from bs4 import BeautifulSoup

from sec_certs.files import search_files
from sec_certs import helpers as helpers
from sec_certs.helpers import find_tables, repair_pdf
from sec_certs.certificate import CommonCriteriaCert, Certificate, FIPSCertificate, FIPSAlgorithm
from sec_certs.extract_certificates import extract_certificates_keywords
from sec_certs.constants import FIPS_NOT_AVAILABLE_CERT_SIZE


class Dataset(ABC):
    def __init__(self, certs: dict, root_dir: Path, name: str = 'dataset name',
                 description: str = 'dataset_description'):
        self.root_dir = root_dir
        self.timestamp = datetime.now()
        self.sha256_digest = 'not implemented'
        self.name = name
        self.description = description
        self.certs = certs

    def __iter__(self):
        for cert in self.certs.values():
            yield cert

    def __getitem__(self, item: str) -> 'Certificate':
        return self.certs.__getitem__(item.lower())

    def __setitem__(self, key: str, value: 'Certificate'):
        self.certs.__setitem__(key.lower(), value)

    def __len__(self) -> int:
        return len(self.certs)

    def __eq__(self, other: 'Dataset') -> bool:
        return self.certs == other.certs

    def __str__(self) -> str:
        return 'Not implemented'

    def to_csv(self):
        pass

    def to_dataframe(self):
        pass

    def to_dict(self):
        return {'root_dir': copy.deepcopy(self.root_dir), 'timestamp': self.timestamp,
                'sha256_digest': self.sha256_digest, 'name': self.name, 'description': self.description,
                'n_certs': len(self), 'certs': list(self.certs.values())}

    @classmethod
    def from_dict(cls, dct: Dict):
        certs = {x.dgst: x for x in dct['certs']}
        return cls(certs, dct['root_dir'], dct['name'], dct['description'])

    @classmethod
    def from_csv(cls):
        pass

    def dump_to_json(self):
        pass

    @abstractmethod
    def get_certs_from_web(self):
        pass

    def merge_certs(self, certs: Dict[str, 'Certificate']):
        """
        Merges dictionary of certificates into the dataset. Assuming they all are CommonCriteria certificates
        """
        will_be_added = {}
        n_merged = 0
        for crt in certs.values():
            if crt not in self:
                will_be_added[crt.dgst] = crt
            else:
                self[crt.dgst].merge(crt)
                n_merged += 1

        self.certs.update(will_be_added)
        logging.info(
            f'Added {len(will_be_added)} new and merged further {n_merged} certificates to the dataset.')


class CCDataset(Dataset):
    @property
    def web_dir(self) -> Path:
        return self.root_dir / 'web'

    html_products = {
        'cc_products_active.html': 'https://www.commoncriteriaportal.org/products/',
        'cc_products_archived.html': 'https://www.commoncriteriaportal.org/products/index.cfm?archived=1',
    }
    html_labs = {'cc_labs.html': 'https://www.commoncriteriaportal.org/labs'}
    csv_products = {
        'cc_products_active.csv': 'https://www.commoncriteriaportal.org/products/certified_products.csv',
        'cc_products_archived.csv': 'https://www.commoncriteriaportal.org/products/certified_products-archived.csv',
    }
    html_pp = {
        'cc_pp_active.html': 'https://www.commoncriteriaportal.org/pps/',
        'cc_pp_collaborative.html': 'https://www.commoncriteriaportal.org/pps/collaborativePP.cfm?cpp=1',
        'cc_pp_archived.html': 'https://www.commoncriteriaportal.org/pps/index.cfm?archived=1',
    }
    csv_pp = {
        'cc_pp_active.csv': 'https://www.commoncriteriaportal.org/pps/pps.csv',
        'cc_pp_archived.csv': 'https://www.commoncriteriaportal.org/pps/pps-archived.csv'
    }

    def get_certs_from_web(self, to_download=True, keep_metadata: bool = True, get_active=True, get_archived=True):
        """
        Downloads all metadata about certificates from CSV and HTML sources
        """
        self.web_dir.mkdir(parents=True, exist_ok=True)

        html_items = [(x, self.web_dir / y)
                      for y, x in self.html_products.items()]
        csv_items = [(x, self.web_dir / y)
                     for y, x in self.csv_products.items()]

        if not get_active:
            html_items = [x for x in html_items if 'active' not in str(x[1])]
            csv_items = [x for x in csv_items if 'active' not in str(x[1])]

        if not get_archived:
            html_items = [x for x in html_items if 'archived' not in str(x[1])]
            csv_items = [x for x in csv_items if 'archived' not in str(x[1])]

        if to_download is True:
            logging.info('Downloading required csv and html files.')
            helpers.download_parallel(html_items, num_threads=8)
            helpers.download_parallel(csv_items, num_threads=8)

        logging.info('Adding CSV certificates to CommonCriteria dataset.')
        csv_certs = self.get_all_certs_from_csv(get_active, get_archived)
        self.merge_certs(csv_certs)

        # TODO: Someway along the way, 3 certificates get lost. Investigate and fix.
        logging.info('Adding HTML certificates to CommonCriteria dataset.')
        html_certs = self.get_all_certs_from_html(get_active, get_archived)
        self.merge_certs(html_certs)

        logging.info(f'The resulting dataset has {len(self)} certificates.')

        if not keep_metadata:
            shutil.rmtree(self.web_dir)

    def get_all_certs_from_csv(self, get_active, get_archived) -> Dict[str, 'CommonCriteriaCert']:
        """
        Creates dictionary of new certificates from csv sources.
        """
        csv_sources = self.csv_products.keys()
        csv_sources = [
            x for x in csv_sources if 'active' not in x or get_active]
        csv_sources = [
            x for x in csv_sources if 'archived' not in x or get_archived]

        new_certs = {}
        for file in csv_sources:
            partial_certs = self.parse_single_csv(self.web_dir / file)
            logging.info(
                f'Parsed {len(partial_certs)} certificates from: {file}')
            new_certs.update(partial_certs)
        return new_certs

    @staticmethod
    def parse_single_csv(file: Path) -> Dict[str, 'CommonCriteriaCert']:
        """
        Using pandas, this parses a single CSV file.
        """

        def get_primary_key_str(row):
            prim_key = row['category'] + row['cert_name'] + row['report_link']
            return prim_key

        csv_header = ['category', 'cert_name', 'manufacturer', 'scheme', 'security_level', 'protection_profiles',
                      'not_valid_before', 'not_valid_after', 'report_link', 'st_link', 'maintainance_date',
                      'maintainance_title', 'maintainance_report_link', 'maintainance_st_link']

        df = pd.read_csv(file, engine='python', encoding='windows-1250')
        df = df.rename(
            columns={x: y for (x, y) in zip(list(df.columns), csv_header)})

        df['is_maintainance'] = ~df.maintainance_title.isnull()
        df = df.fillna(value='')

        df[['not_valid_before', 'not_valid_after', 'maintainance_date']] = df[
            ['not_valid_before', 'not_valid_after', 'maintainance_date']].apply(pd.to_datetime)

        df['dgst'] = df.apply(lambda row: helpers.get_first_16_bytes_sha256(
            get_primary_key_str(row)), axis=1)
        df_base = df.loc[df.is_maintainance == False].copy()
        df_main = df.loc[df.is_maintainance == True].copy()

        n_all = len(df_base)
        n_deduplicated = len(df_base.drop_duplicates(subset=['dgst']))
        if (n_dup := n_all - n_deduplicated) > 0:
            logging.warning(
                f'The CSV {file} contains {n_dup} duplicates by the primary key.')

        df_base = df_base.drop_duplicates(subset=['dgst'])
        df_main = df_main.drop_duplicates()

        profiles = {x.dgst: set([CommonCriteriaCert.ProtectionProfile(y, None) for y in
                                 helpers.sanitize_protection_profiles(x.protection_profiles)]) for x in
                    df_base.itertuples()}
        updates = {x.dgst: set() for x in df_base.itertuples()}
        for x in df_main.itertuples():
            updates[x.dgst].add(CommonCriteriaCert.MaintainanceReport(x.maintainance_date.date(), x.maintainance_title,
                                                                      x.maintainance_report_link,
                                                                      x.maintainance_st_link))

        certs = {x.dgst: CommonCriteriaCert(x.category, x.cert_name, x.manufacturer, x.scheme, x.security_level,
                                            x.not_valid_before, x.not_valid_after, x.report_link, x.st_link, 'csv',
                                            None, None, profiles.get(x.dgst, None), updates.get(x.dgst, None)) for x in
                 df_base.itertuples()}
        return certs

    def get_all_certs_from_html(self, get_active, get_archived) -> Dict[str, 'CommonCriteriaCert']:
        """
        Prepares dictionary of certificates from all html files.
        """
        html_sources = self.html_products.keys()
        html_sources = [
            x for x in html_sources if 'active' not in x or get_active]
        html_sources = [
            x for x in html_sources if 'archived' not in x or get_archived]

        new_certs = {}
        for file in html_sources:
            partial_certs = self.parse_single_html(self.web_dir / file)
            logging.info(
                f'Parsed {len(partial_certs)} certificates from: {file}')
            new_certs.update(partial_certs)
        return new_certs

    @staticmethod
    def parse_single_html(file: Path) -> Dict[str, 'CommonCriteriaCert']:
        """
        Prepares a dictionary of certificates from a single html file.
        """

        def get_timestamp_from_footer(footer):
            locale.setlocale(locale.LC_ALL, 'en_US')
            footer_text = list(footer.stripped_strings)[0]
            date_string = footer_text.split(',')[1:3]
            time_string = footer_text.split(',')[3].split(' at ')[1]
            formatted_datetime = date_string[0] + \
                                 date_string[1] + ' ' + time_string
            return datetime.strptime(formatted_datetime, ' %B %d %Y %I:%M %p')

        def parse_table(soup: BeautifulSoup, table_id: str, category_string: str) -> Dict[str, 'CommonCriteriaCert']:
            tables = soup.find_all('table', id=table_id)
            assert len(tables) <= 1

            if not tables:
                return {}

            table = tables[0]
            rows = list(table.find_all('tr'))
            header, footer, body = rows[0], rows[1], rows[2:]

            # TODO: It's possible to obtain timestamp of the moment when the list was generated. It's identical for each table and should thus only be obtained once. Not necessarily in each table
            # timestamp = get_timestamp_from_footer(footer)

            # TODO: Do we have use for number of expected certs? We get rid of duplicites, so no use for assert expected == actual
            # caption_str = str(table.findAll('caption'))
            # n_expected_certs = int(caption_str.split(category_string + ' – ')[1].split(' Certified Products')[0])
            table_certs = {x.dgst: x for x in [
                CommonCriteriaCert.from_html_row(row, category_string) for row in body]}

            return table_certs

        cc_cat_abbreviations = ['AC', 'BP', 'DP', 'DB', 'DD', 'IC', 'KM',
                                'MD', 'MF', 'NS', 'OS', 'OD', 'DG', 'TC']
        cc_table_ids = ['tbl' + x for x in cc_cat_abbreviations]
        cc_categories = ['Access Control Devices and Systems',
                         'Boundary Protection Devices and Systems',
                         'Data Protection',
                         'Databases',
                         'Detection Devices and Systems',
                         'ICs, Smart Cards and Smart Card-Related Devices and Systems',
                         'Key Management Systems',
                         'Mobility',
                         'Multi-Function Devices',
                         'Network and Network-Related Devices and Systems',
                         'Operating Systems',
                         'Other Devices and Systems',
                         'Products for Digital Signatures',
                         'Trusted Computing'
                         ]
        cat_dict = {x: y for (x, y) in zip(cc_table_ids, cc_categories)}

        with open(file, 'r') as handle:
            soup = BeautifulSoup(handle, 'html.parser')

        certs = {}
        for key, val in cat_dict.items():
            certs.update(parse_table(soup, key, val))

        return certs


class FIPSDataset(Dataset):
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
            elif os.path.getsize(self.policies_dir / f'{i}.pdf') < FIPS_NOT_AVAILABLE_CERT_SIZE:
                not_available.append(i)
        return missing, not_available

    def extract_keywords(self):
        self.fragments_dir.mkdir(parents=True, exist_ok=True)
        if self.new_files > 0 or not (self.root_dir / 'fips_full_keywords.json').exists():
            self.keywords = extract_certificates_keywords(
                self.policies_dir,
                self.fragments_dir, 'fips', fips_items=self.certs,
                should_censure_right_away=True)
        else:
            self.keywords = json.loads(
                open(self.root_dir / 'fips_full_keywords.json').read())

    def dump_to_json(self):
        with open(self.root_dir / 'fips_full_dataset.json', 'w') as handle:
            json.dump(self, handle, cls=import_module(
                'sec_certs.serialization').CustomJSONEncoder, indent=4)

    def dump_keywords(self):
        with open(self.root_dir / "fips_full_keywords.json", 'w') as f:
            f.write(json.dumps(self.keywords, indent=4, sort_keys=True))

    # TODO figure out whether the name of this method shuold not be "get_certs", because we don't download every time

    def get_certs_from_web(self):
        def download_html_pages() -> Tuple[int, int]:
            html_items = [
                (f"https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/{cert_id}",
                 self.web_dir / f"{cert_id}.html") for cert_id in list(self.certs.keys()) if
                not (self.web_dir / f'{cert_id}.html').exists()]
            sp_items = [(
                f"https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp{cert_id}.pdf",
                self.policies_dir / f"{cert_id}.pdf") for cert_id in list(self.certs.keys()) if
                not (self.policies_dir / f'{cert_id}.pdf').exists()]

            logging.info(f"downloading {len(html_items) + len(sp_items)} module html and pdf files")
            _, self.new_files = helpers.download_parallel(
                html_items + sp_items, 8), len(html_items) + len(sp_items)

            pages = [
                (
                    f'https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/validation-search?searchMode=validation&page={i}',
                    self.algs_dir / f'page{i}.html'
                ) for i in range(1, 502) if not (self.algs_dir / f'page{i}.html').exists()
            ]

            logging.info(f"downloading {len(pages)} algorithm html files")
            helpers.download_parallel(pages, 8)

            return len(html_items) + len(sp_items), len(pages)

        def get_certificates_from_html(html_file: Path) -> None:
            logging.info(f'Getting certificate ids from {html_file}')
            html = BeautifulSoup(open(html_file).read(), 'html.parser')

            table = [x for x in html.find(
                id='searchResultsTable').tbody.contents if x != '\n']
            for entry in table:
                self.certs[entry.find('a').text] = {}

        logging.info("Downloading required html files")

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

        logging.info('Downloading certficate html and security policies')
        self.new_files, new_algs = download_html_pages()

        logging.info(f"{self.new_files} needed to be downloaded")

        if self.new_files > 0 or not (self.root_dir / 'fips_full_dataset.json').exists():
            for cert in self.certs:
                self.certs[cert] = FIPSCertificate.html_from_file(
                    self.web_dir / f'{cert}.html')
        else:
            logging.info("Certs loaded from previous scanning")
            dataset = json.loads(open(self.root_dir / 'fips_full_dataset.json').read(),
                                 cls=import_module('sec_certs.serialization').CustomJSONDecoder)
            self.certs = dataset.certs

    def extract_certs_from_tables(self) -> List[Path]:
        """
        Function that extracts algorithm IDs from tables in security policies files.
        :return: list of files that couldn't have been decoded
        """

        list_of_files = search_files(self.policies_dir)
        not_decoded = []
        for cert_file in list_of_files:
            cert_file = Path(cert_file)

            if '.txt' not in cert_file.suffixes:
                continue

            stem_name = Path(cert_file.stem).stem

            if self.certs[stem_name].tables_done:
                continue

            with open(cert_file, 'r') as f:
                tables = find_tables(f.read(), cert_file)

            # If we find any tables with page numbers, we process them
            if tables:
                lst = []
                try:
                    data = read_pdf(cert_file.with_suffix(''),
                                    pages=tables, silent=True)
                except Exception:
                    try:
                        repair_pdf(cert_file.with_suffix(''))
                        data = read_pdf(cert_file.with_suffix(
                            ''), pages=tables, silent=True)

                    except Exception:
                        not_decoded.append(cert_file)
                        continue

                # find columns with cert numbers
                for df in data:
                    for col in range(len(df.columns)):
                        if 'cert' in df.columns[col].lower() or 'algo' in df.columns[col].lower():
                            lst += FIPSCertificate.parse_algorithms(
                                df.iloc[:, col].to_string(index=False), True)

                    # Parse again if someone picks not so descriptive column names
                    lst += FIPSCertificate.parse_algorithms(
                        df.to_string(index=False))

                if lst:
                    self.certs[stem_name].algorithms += lst

            self.certs[stem_name].tables_done = True
        return not_decoded

    def remove_algorithms_from_extracted_data(self):
        """
        Function that removes all found certificate IDs that are matching any IDs labeled as algorithm IDs
        """
        for file_name in self.keywords:
            self.keywords[file_name]['file_status'] = True
            self.certs[file_name].file_status = True
            if self.certs[file_name].mentioned_certs:
                for item in self.certs[file_name].mentioned_certs:
                    self.keywords[file_name]['rules_cert_id'].update(item)

            for rule in self.keywords[file_name]['rules_cert_id']:
                to_pop = set()
                rr = re.compile(rule)
                for cert in self.keywords[file_name]['rules_cert_id'][rule]:
                    for alg in self.keywords[file_name]['rules_fips_algorithms']:
                        for found in self.keywords[file_name]['rules_fips_algorithms'][alg]:
                            if rr.search(found) and rr.search(cert) and rr.search(found).group('id') == rr.search(
                                    cert).group('id'):
                                to_pop.add(cert)
                for r in to_pop:
                    self.keywords[file_name]['rules_cert_id'][rule].pop(
                        r, None)

                self.keywords[file_name]['rules_cert_id'][rule].pop(
                    self.certs[file_name].cert_id, None)

    def unify_algorithms(self):
        for certificate in self.certs.values():
            new_algorithms = []
            for algorithm in certificate.algorithms:
                if isinstance(algorithm, dict):
                    new_algorithms.append(algorithm)
                else:
                    new_algorithms.append({'Certificate': algorithm})
            certificate.algorithms = new_algorithms

    def validate_results(self):
        """
        Function that validates results and finds the final connection output
        """
        def validate_id(processed_cert: FIPSCertificate, cert_candidate: str) -> bool:
            # TODO: do we do this? #1 is used a lot
            if cert_candidate == '1':
                return False
            if cert_candidate not in self.algorithms.certs:
                return True

            for cert_alg in processed_cert.algorithms:
                for certificate in cert_alg['Certificate']:
                    print(certificate)
                    curr_id = ''.join(filter(str.isdigit, certificate))
                    if curr_id == cert_candidate:
                        return False

            algs = self.algorithms.certs[cert_candidate]
            for current_alg in algs:
                if processed_cert.vendor[:3] in current_alg.vendor:
                    return False
            return True

        broken_files = set()
        for file_name in self.keywords:
            for rule in self.keywords[file_name]['rules_cert_id']:
                for cert in self.keywords[file_name]['rules_cert_id'][rule]:
                    cert_id = ''.join(filter(str.isdigit, cert))

                    if cert_id == '' or cert_id not in self.certs:
                        broken_files.add(file_name)
                        self.keywords[file_name]['file_status'] = False
                        self.certs[file_name].file_status = False
                        break

        if broken_files:
            logging.warning("CERTIFICATE FILES WITH WRONG CERTIFICATES PARSED")
            logging.warning(broken_files)
            logging.warning("... skipping these...")
            logging.warning(f"Total non-analyzable files:{len(broken_files)}")

        for file_name in self.keywords:
            self.certs[file_name].connections = []
            if not self.keywords[file_name]['file_status']:
                continue
            if self.keywords[file_name]['rules_cert_id'] == {}:
                continue
            for rule in self.keywords[file_name]['rules_cert_id']:
                for cert in self.keywords[file_name]['rules_cert_id'][rule]:
                    cert_id = ''.join(filter(str.isdigit, cert))
                    if cert_id not in self.certs[file_name].connections and validate_id(self.certs[file_name], cert_id):
                        self.certs[file_name].connections.append(cert_id)

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
            if self.certs[current_key].vendor == highlighted_vendor:
                dot.attr('node', color='red')
                if self.certs[current_key].status == 'Revoked':
                    dot.attr('node', color='grey32')
                if self.certs[current_key].status == 'Historical':
                    dot.attr('node', color='gold3')
            if self.certs[current_key].vendor == "SUSE, LLC":
                dot.attr('node', color='lightblue')

        def color_check(current_key):
            dot.attr('node', color='lightgreen')
            if self.certs[current_key].status == 'Revoked':
                dot.attr('node', color='lightgrey')
            if self.certs[current_key].status == 'Historical':
                dot.attr('node', color='gold')
            found_interesting_cert(current_key)
            dot.node(current_key, label=current_key + '\n' + self.certs[current_key].vendor +
                                        ('\n' + self.certs[current_key].module_name
                                         if self.certs[current_key].module_name else ''))

        keys = 0
        edges = 0

        highlighted_vendor = 'Red Hat®, Inc.'
        for key in self.certs:
            if key != 'Not found' and self.certs[key].file_status:
                if self.certs[key].connections:
                    color_check(key)
                    keys += 1
                else:
                    single_dot.attr('node', color='lightblue')
                    found_interesting_cert(key)
                    single_dot.node(key, label=key + '\n' + self.certs[key].vendor + (
                        '\n' + self.certs[key].module_name if self.certs[key].module_name else ''))

        for key in self.certs:
            if key != 'Not found' and self.certs[key].file_status:
                for conn in self.certs[key].connections:
                    color_check(conn)
                    dot.edge(key, conn)
                    edges += 1

        logging.info(f"rendering {keys} keys and {edges} edges")

        dot.render(str(output_file_name) + '_connections', view=True)
        single_dot.render(str(output_file_name) + '_single', view=True)


class AlgorithmDataset(Dataset):

    def get_certs_from_web(self):
        pass

    def parse_html(self):
        def split_alg(alg_string):
            cert_type = alg_string.rstrip('0123456789')
            cert_id = alg_string[len(cert_type):]
            return cert_type.strip(), cert_id.strip()

        for f in search_files(self.root_dir):
            html_soup = BeautifulSoup(open(f).read(), 'html.parser')
            table = html_soup.find('table', class_='table table-condensed publications-table table-bordered')
            spans = table.find_all('span')
            for span in spans:
                elements = span.find_all('td')
                vendor, implementation = elements[0].text, elements[1].text
                elements_sliced = elements[2:]
                for i in range(0, len(elements_sliced), 2):
                    alg_type, alg_id = split_alg(elements_sliced[i].text.strip())
                    validation_date = elements_sliced[i + 1].text.strip()
                    fips_alg = FIPSAlgorithm(alg_id, vendor, implementation, alg_type, validation_date)
                    if alg_id not in self.certs:
                        self.certs[alg_id] = []
                    self.certs[alg_id].append(fips_alg)

