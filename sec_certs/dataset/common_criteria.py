import copy
import itertools
import locale
import shutil
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Union, List
import json

import pandas as pd
from bs4 import Tag, BeautifulSoup

from sec_certs import helpers as helpers, cert_processing as cert_processing, constants as constants
from sec_certs.dataset.cpe import CPEDataset
from sec_certs.dataset.cve import CVEDataset
from sec_certs.dataset.dataset import Dataset, logger
from sec_certs.serialization import ComplexSerializableType
from sec_certs.certificate.common_criteria import CommonCriteriaCert


class CCDataset(Dataset, ComplexSerializableType):
    # TODO: Make properties propagate to changing internal state of related certificates
    @dataclass
    class DatasetInternalState(ComplexSerializableType):
        meta_sources_parsed: bool = False
        pdfs_downloaded: bool = False
        pdfs_converted: bool = False
        txt_data_extracted: bool = False
        certs_analyzed: bool = False

        def to_dict(self):
            return copy.deepcopy(self.__dict__)

        @classmethod
        def from_dict(cls, dct: Dict[str, bool]):
            return cls(*tuple(dct.values()))

    certs: Dict[str, 'CommonCriteriaCert']

    def __init__(self, certs: Dict[str, 'CommonCriteriaCert'], root_dir: Path, name: str = 'dataset name',
                 description: str = 'dataset_description', state: Optional[DatasetInternalState] = None):
        super().__init__(certs, root_dir, name, description)

        if state is None:
            state = self.DatasetInternalState()
        self.state = state

    def __iter__(self) -> CommonCriteriaCert:
        yield from self.certs.values()

    def to_dict(self):
        return {**{'state': self.state}, **super().to_dict()}

    def to_pandas(self):
        tuples = [x.to_pandas_tuple() for x in self.certs.values()]
        cols = CommonCriteriaCert.pandas_columns

        df = pd.DataFrame(tuples, columns=cols)
        df = df.set_index('dgst')

        df.not_valid_before = pd.to_datetime(df.not_valid_before, infer_datetime_format=True)
        df.not_valid_after = pd.to_datetime(df.not_valid_after, infer_datetime_format=True)
        df = df.astype({'category': 'category', 'status': 'category', 'scheme': 'category'})

        return df

    @classmethod
    def from_dict(cls, dct: Dict):
        dset = super().from_dict(dct)
        dset.state = copy.deepcopy(dct['state'])
        return dset

    @Dataset.root_dir.setter
    def root_dir(self, new_dir: Union[str, Path]):
        Dataset.root_dir.fset(self, new_dir)
        self.set_local_paths()

    @property
    def web_dir(self) -> Path:
        return self.root_dir / 'web'

    @property
    def certs_dir(self) -> Path:
        return self.root_dir / 'certs'

    @property
    def reports_dir(self) -> Path:
        return self.certs_dir / 'reports'

    @property
    def reports_pdf_dir(self) -> Path:
        return self.reports_dir / 'pdf'

    @property
    def reports_txt_dir(self) -> Path:
        return self.reports_dir / 'txt'

    @property
    def targets_dir(self) -> Path:
        return self.certs_dir / 'targets'

    @property
    def targets_pdf_dir(self) -> Path:
        return self.targets_dir / 'pdf'

    @property
    def targets_txt_dir(self) -> Path:
        return self.targets_dir / 'txt'

    @property
    def auxillary_datasets_path(self) -> Path:
        return self.root_dir / 'auxillary_datasets'

    @property
    def cve_dataset_path(self) -> Path:
        return self.auxillary_datasets_path / 'cve_dataset.json'

    @property
    def cpe_dataset_path(self) -> Path:
        return self.auxillary_datasets_path / 'cpe_dataset.json'

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

    @classmethod
    def from_json(cls, input_path: Union[str, Path]):
        dset = super().from_json(input_path)
        dset.set_local_paths()
        return dset

    def set_local_paths(self):
        for cert in self:
            cert.set_local_paths(self.reports_pdf_dir, self.targets_pdf_dir, self.reports_txt_dir, self.targets_txt_dir)

    def _merge_certs(self, certs: Dict[str, 'CommonCriteriaCert']):
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
        logger.info(
            f'Added {len(will_be_added)} new and merged further {n_merged} certificates to the dataset.')

    def get_certs_from_web(self, to_download: bool = True, keep_metadata: bool = True, get_active: bool = True,
                           get_archived: bool = True, update_json: bool = True):
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

        html_urls, html_paths = [x[0] for x in html_items], [x[1] for x in html_items]
        csv_urls, csv_paths = [x[0] for x in csv_items], [x[1] for x in csv_items]

        if to_download is True:
            logger.info('Downloading required csv and html files.')
            self._download_parallel(html_urls, html_paths)
            self._download_parallel(csv_urls, csv_paths)

        logger.info('Adding CSV certificates to CommonCriteria dataset.')
        csv_certs = self._get_all_certs_from_csv(get_active, get_archived)
        self._merge_certs(csv_certs)

        # TODO: Someway along the way, 3 certificates get lost. Investigate and fix.
        logger.info('Adding HTML certificates to CommonCriteria dataset.')
        html_certs = self._get_all_certs_from_html(get_active, get_archived)
        self._merge_certs(html_certs)

        logger.info(f'The resulting dataset has {len(self)} certificates.')

        if not keep_metadata:
            shutil.rmtree(self.web_dir)

        self.set_local_paths()
        self.state.meta_sources_parsed = True

        if update_json is True:
            self.to_json(self.json_path)

    def _get_all_certs_from_csv(self, get_active: bool, get_archived: bool) -> Dict[str, 'CommonCriteriaCert']:
        """
        Creates dictionary of new certificates from csv sources.
        """
        csv_sources = self.csv_products.keys()
        csv_sources = [x for x in csv_sources if 'active' not in x or get_active]
        csv_sources = [x for x in csv_sources if 'archived' not in x or get_archived]

        new_certs = {}
        for file in csv_sources:
            partial_certs = self._parse_single_csv(self.web_dir / file)
            logger.info(
                f'Parsed {len(partial_certs)} certificates from: {file}')
            new_certs.update(partial_certs)
        return new_certs

    @staticmethod
    def _parse_single_csv(file: Path) -> Dict[str, 'CommonCriteriaCert']:
        """
        Using pandas, this parses a single CSV file.
        """

        def _get_primary_key_str(row: Tag):
            prim_key = row['category'] + row['cert_name'] + row['report_link']
            return prim_key

        if 'active' in str(file):
            cert_status = 'active'
        else:
            cert_status = 'archived'

        csv_header = ['category', 'cert_name', 'manufacturer', 'scheme', 'security_level', 'protection_profiles',
                      'not_valid_before', 'not_valid_after', 'report_link', 'st_link', 'maintainance_date',
                      'maintainance_title', 'maintainance_report_link', 'maintainance_st_link']

        # TODO: Now skipping bad lines, smarter heuristics to be built for dumb files
        df = pd.read_csv(file, engine='python', encoding='windows-1252', error_bad_lines=False)
        df = df.rename(columns={x: y for (x, y) in zip(list(df.columns), csv_header)})

        df['is_maintainance'] = ~df.maintainance_title.isnull()
        df = df.fillna(value='')

        df[['not_valid_before', 'not_valid_after', 'maintainance_date']] = df[
            ['not_valid_before', 'not_valid_after', 'maintainance_date']].apply(pd.to_datetime)

        df['dgst'] = df.apply(lambda row: helpers.get_first_16_bytes_sha256(
            _get_primary_key_str(row)), axis=1)
        df_base = df.loc[df.is_maintainance == False].copy()
        df_main = df.loc[df.is_maintainance == True].copy()

        n_all = len(df_base)
        n_deduplicated = len(df_base.drop_duplicates(subset=['dgst']))
        if (n_dup := n_all - n_deduplicated) > 0:
            logger.warning(
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

        certs = {
            x.dgst: CommonCriteriaCert(cert_status, x.category, x.cert_name, x.manufacturer, x.scheme, x.security_level,
                                       x.not_valid_before, x.not_valid_after, x.report_link, x.st_link, 'csv',
                                       None, None, profiles.get(x.dgst, None), updates.get(x.dgst, None), None, None,
                                       None) for
            x in
            df_base.itertuples()}
        return certs

    def _get_all_certs_from_html(self, get_active: bool, get_archived: bool) -> Dict[str, 'CommonCriteriaCert']:
        """
        Prepares dictionary of certificates from all html files.
        """
        html_sources = self.html_products.keys()
        if get_active is False:
            html_sources = filter(lambda x: 'active' not in x, html_sources)
        if get_archived is False:
            html_sources = filter(lambda x: 'archived' not in x, html_sources)

        new_certs = {}
        for file in html_sources:
            partial_certs = self._parse_single_html(self.web_dir / file)
            logger.info(
                f'Parsed {len(partial_certs)} certificates from: {file}')
            new_certs.update(partial_certs)
        return new_certs

    @staticmethod
    def _parse_single_html(file: Path) -> Dict[str, 'CommonCriteriaCert']:
        """
        Prepares a dictionary of certificates from a single html file.
        """

        def _get_timestamp_from_footer(footer):
            locale.setlocale(locale.LC_ALL, 'en_US')
            footer_text = list(footer.stripped_strings)[0]
            date_string = footer_text.split(',')[1:3]
            time_string = footer_text.split(',')[3].split(' at ')[1]
            formatted_datetime = date_string[0] + \
                                 date_string[1] + ' ' + time_string
            return datetime.strptime(formatted_datetime, ' %B %d %Y %I:%M %p')

        def _parse_table(soup: BeautifulSoup, cert_status: str, table_id: str, category_string: str) -> Dict[
            str, 'CommonCriteriaCert']:
            tables = soup.find_all('table', id=table_id)
            assert len(tables) <= 1

            if not tables:
                return {}

            table = tables[0]
            rows = list(table.find_all('tr'))
            header, footer, body = rows[0], rows[1], rows[2:]

            # TODO: It's possible to obtain timestamp of the moment when the list was generated. It's identical for each table and should thus only be obtained once. Not necessarily in each table
            # timestamp = _get_timestamp_from_footer(footer)

            # TODO: Do we have use for number of expected certs? We get rid of duplicites, so no use for assert expected == actual
            # caption_str = str(table.findAll('caption'))
            # n_expected_certs = int(caption_str.split(category_string + ' – ')[1].split(' Certified Products')[0])
            table_certs = {x.dgst: x for x in [
                CommonCriteriaCert.from_html_row(row, cert_status, category_string) for row in body]}

            return table_certs

        if 'active' in str(file):
            cert_status = 'active'
        else:
            cert_status = 'archived'

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

        with file.open('r') as handle:
            soup = BeautifulSoup(handle, 'html.parser')

        certs = {}
        for key, val in cat_dict.items():
            certs.update(_parse_table(soup, cert_status, key, val))

        return certs

    def _download_reports(self, fresh=True):
        self.reports_pdf_dir.mkdir(parents=True, exist_ok=True)

        if fresh is True:
            certs_to_process = self.certs.values()
        else:
            certs_to_process = [x for x in self.certs.values() if not x.state.report_link_ok]

        cert_processing.process_parallel(CommonCriteriaCert.download_pdf_report, certs_to_process, constants.N_THREADS)

    def _download_targets(self, fresh=True):
        self.targets_pdf_dir.mkdir(parents=True, exist_ok=True)

        if fresh is True:
            certs_to_process = self.certs.values()
        else:
            certs_to_process = [x for x in self.certs.values() if not x.state.st_link_ok]

        cert_processing.process_parallel(CommonCriteriaCert.download_pdf_target, certs_to_process, constants.N_THREADS)

    def download_all_pdfs(self, fresh: bool = True, update_json: bool = False):
        if self.state.meta_sources_parsed is False:
            logger.error('Attempting to download pdfs while not having csv/html meta-sources parsed. Returning.')
            return

        logger.info('Downloading CC certificate reports')
        self._download_reports(fresh)

        logger.info('Downloading CC security targets')
        self._download_targets(fresh)

        if fresh is True:
            # Attempt to re-download once if some files are missing
            if any(filter(lambda x: not x.state.report_link_ok, self.certs.values())):
                logger.info('Attempting to re-download failed report links.')
                self._download_reports(False)

            if any(filter(lambda x: not x.state.st_link_ok, self.certs.values())):
                logger.info('Attempting to re-download failed security target links.')
                self._download_targets(False)

        self.state.pdfs_downloaded = True

        if update_json is True:
            self.to_json(self.json_path)

    def _convert_reports_to_txt(self, fresh: bool = True):
        self.reports_txt_dir.mkdir(parents=True, exist_ok=True)

        if fresh is True:
            certs_to_process = [x for x in self.certs.values() if x.state.report_link_ok]
        else:
            certs_to_process = [x for x in self.certs.values() if
                                x.state.report_link_ok and not x.state.report_convert_ok]
        cert_processing.process_parallel(CommonCriteriaCert.convert_report_pdf, certs_to_process, constants.N_THREADS)

    def _convert_targets_to_txt(self, fresh: bool = True):
        self.targets_txt_dir.mkdir(parents=True, exist_ok=True)

        if fresh is True:
            certs_to_process = [x for x in self.certs.values() if x.state.st_link_ok]
        else:
            certs_to_process = [x for x in self.certs.values() if x.state.st_link_ok and not x.state.st_convert_ok]
        cert_processing.process_parallel(CommonCriteriaCert.convert_target_pdf, certs_to_process, constants.N_THREADS)

    def convert_all_pdfs(self, fresh: bool = True, update_json: bool = False):
        if self.state.pdfs_downloaded is False:
            logger.info('Attempting to convert pdf while not having them downloaded. Returning.')
            return

        logger.info('Converting CC certificate reports to .txt')
        self._convert_reports_to_txt(fresh)

        logger.info('Converting CC security targets to .txt')
        self._convert_targets_to_txt(fresh)

        if fresh is True:
            # Attempt to re-convert once if some files failed but downloads are ok
            if any(filter(lambda x: x.state.report_link_ok and not x.state.report_convert_ok, self.certs.values())):
                logger.info('Attempting to re-convert failed report pdfs')
                self._convert_reports_to_txt(False)
            if any(filter(lambda x: x.state.st_link_ok and not x.state.st_convert_ok, self.certs.values())):
                logger.info('Attempting to re-convert failed target pdfs')
                self._convert_targets_to_txt(False)

        self.state.pdfs_converted = True

        if update_json is True:
            self.to_json(self.json_path)

    def _extract_report_metadata(self, fresh: bool = True):
        if fresh is True:
            certs_to_process = [x for x in self.certs.values() if x.state.report_convert_ok]
        else:
            certs_to_process = [x for x in self.certs.values() if
                                x.state.report_convert_ok and not x.state.report_extract_ok]
        cert_processing.process_parallel(CommonCriteriaCert.extract_report_pdf_metadata, certs_to_process,
                                         constants.N_THREADS)

    def _extract_targets_metadata(self, fresh: bool = True):
        if fresh is True:
            certs_to_process = [x for x in self.certs.values() if x.state.st_convert_ok]
        else:
            certs_to_process = [x for x in self.certs.values() if x.state.st_convert_ok and not x.state.st_extract_ok]
        cert_processing.process_parallel(CommonCriteriaCert.extract_st_pdf_metadata, certs_to_process,
                                         constants.N_THREADS)

    def extract_pdf_metadata(self, fresh: bool = True):
        logger.info('Extracting pdf metadata from CC dataset')
        self._extract_report_metadata(fresh)
        self._extract_targets_metadata(fresh)

    def _extract_targets_frontpage(self, fresh: bool = True):
        if fresh is True:
            certs_to_process = [x for x in self.certs.values() if x.state.st_convert_ok]
        else:
            certs_to_process = [x for x in self.certs.values() if x.state.st_convert_ok and not x.state.st_extract_ok]
        cert_processing.process_parallel(CommonCriteriaCert.extract_st_pdf_frontpage, certs_to_process,
                                         constants.N_THREADS)

    def _extract_report_frontpage(self, fresh: bool = True):
        if fresh is True:
            certs_to_process = [x for x in self.certs.values() if x.state.report_convert_ok]
        else:
            certs_to_process = [x for x in self.certs.values() if
                                x.state.report_convert_ok and not x.state.report_extract_ok]
        cert_processing.process_parallel(CommonCriteriaCert.extract_report_pdf_frontpage, certs_to_process,
                                         constants.N_THREADS)

    def extract_pdf_frontpage(self, fresh: bool = True):
        logger.info('Extracting pdf frontpages from CC dataset.')
        self._extract_report_frontpage(fresh)
        self._extract_targets_frontpage(fresh)

    def _extract_report_keywords(self, fresh: bool = True):
        if fresh is True:
            certs_to_process = [x for x in self.certs.values() if x.state.report_convert_ok]
        else:
            certs_to_process = [x for x in self.certs.values() if
                                x.state.report_convert_ok and not x.state.report_extract_ok]
        cert_processing.process_parallel(CommonCriteriaCert.extract_report_pdf_keywords, certs_to_process,
                                         constants.N_THREADS)

    def _extract_targets_keywords(self, fresh: bool = True):
        if fresh is True:
            certs_to_process = [x for x in self.certs.values() if x.state.st_convert_ok]
        else:
            certs_to_process = [x for x in self.certs.values() if x.state.st_convert_ok and not x.state.st_extract_ok]
        cert_processing.process_parallel(CommonCriteriaCert.extract_st_pdf_keywords, certs_to_process,
                                         constants.N_THREADS)

    def extract_pdf_keywords(self, fresh: bool = True):
        logger.info('Extracting pdf keywords from CC dataset.')
        self._extract_report_keywords(fresh)
        self._extract_targets_keywords(fresh)

    def extract_data(self, fresh: bool = True, update_json: bool = False):
        if self.state.pdfs_converted is False:
            logger.info('Attempting to extract data from txt while not having the pdf->txt conversion done. Returning.')
            return

        logger.info('Extracting various stuff from converted txt filed from CC dataset.')
        self.extract_pdf_metadata(fresh)
        self.extract_pdf_frontpage(fresh)
        self.extract_pdf_keywords(fresh)

        if fresh is True:
            if any(filter(lambda x: x.state.report_convert_ok and not x.state.report_extract_ok, self.certs.values())):
                logger.info('Attempting to re-extract failed data from report txts')
                self._extract_report_metadata(False)
                self._extract_report_frontpage(False)
                self._extract_report_keywords(False)
            if any(filter(lambda x: x.state.st_convert_ok and not x.state.st_extract_ok, self.certs.values())):
                logger.info('Attempting to re-extract failed data from ST txts')
                self._extract_targets_metadata(False)
                self._extract_targets_frontpage(False)
                self._extract_targets_keywords(False)

        self.state.txt_data_extracted = True

        if update_json is True:
            self.to_json(self.json_path)

    def prepare_cpe_dataset(self, download_fresh_cpes: bool = False) -> CPEDataset:
        logger.info('Preparing CPE dataset.')
        if not self.auxillary_datasets_path.exists():
            self.auxillary_datasets_path.mkdir(parents=True)

        if not self.cpe_dataset_path.exists() or download_fresh_cpes is True:
            cpe_dataset = CPEDataset.from_web()
            cpe_dataset.to_json(str(self.cpe_dataset_path))
        else:
            cpe_dataset = CPEDataset.from_json(str(self.cpe_dataset_path))

        return cpe_dataset

    def prepare_cve_dataset(self, download_fresh_cves: bool = False) -> CVEDataset:
        logger.info('Preparing CVE dataset.')
        if not self.auxillary_datasets_path.exists():
            self.auxillary_datasets_path.mkdir(parents=True)

        if not self.cve_dataset_path.exists() or download_fresh_cves is True:
            cve_dataset = CVEDataset.from_web()
            cve_dataset.to_json(str(self.cve_dataset_path))
        else:
            cve_dataset = CVEDataset.from_json(str(self.cve_dataset_path))

        return cve_dataset

    def compute_heuristics(self, update_json=True, download_fresh_cpes: bool = False):
        def compute_candidate_versions():
            logger.info('Computing heuristics: possible product versions in certificate name')
            for cert in self:
                cert.compute_heuristics_version()

        def compute_cpe_matches(cpe_dataset: CPEDataset):
            logger.info('Computing heuristics: Finding CPE matches for certificates')
            for cert in self:
                cert.compute_heuristics_cpe_match(cpe_dataset)

        def compute_cert_labs():
            logger.info('Deriving information about laboratories involved in certification.')
            for cert in self:
                cert.compute_heuristics_cert_lab()

        def compute_cert_ids():
            logger.info('Deriving information about certificate ids from pdf scan.')
            for cert in self:
                cert.compute_heuristics_cert_id()

        compute_candidate_versions()
        cpe_dset = self.prepare_cpe_dataset(download_fresh_cpes)
        compute_cpe_matches(cpe_dset)
        # compute_cert_labs()
        # compute_cert_ids()

        if update_json is True:
            self.to_json(self.json_path)

    def manually_verify_cpe_matches(self, update_json=True):
        def verify_certs(certificates_to_verify: List[CommonCriteriaCert]):
            n_certs_to_verify = len(certificates_to_verify)
            for i, x in enumerate(certificates_to_verify):
                print(f'\n[{i}/{n_certs_to_verify}] Vendor: {x.manufacturer}, Name: {x.name}')
                for index, c in enumerate(x.heuristics.cpe_matches):
                    print(f'\t- {[index]}: {c[1].vendor} {c[1].title} CPE-URI: {c[1].uri}')
                print(f'\t- [A]: All are fitting')
                print(f'\t- [X]: No fitting match')
                inpts = input('Select fitting CPE matches (split with comma if choosing more):').strip().split(',')

                if 'X' not in inpts and 'x' not in inpts:
                    if 'A' in inpts or 'a' in inpts:
                        inpts = [x for x in range(0, len(x.heuristics.cpe_matches))]
                    try:
                        inpts = [int(x) for x in inpts]
                        if min(inpts) < 0 or max(inpts) > len(x.heuristics.cpe_matches) - 1:
                            raise ValueError(f'Incorrect number chosen, choose in range 0-{len(x.heuristics.cpe_matches) - 1}')
                    except ValueError as e:
                        logger.error(f'Bad input from user, repeating instance: {e}')
                        print(f'Bad input from user, repeating instance: {e}')
                        time.sleep(0.05)
                        verify_certs([x])
                    else:
                        matches = [x.heuristics.cpe_matches[y][1] for y in inpts]
                        self[x.dgst].heuristics.verified_cpe_matches = matches

                if i != 0 and not i % 10 and update_json:
                    print(f'Saving progress.')
                    self.to_json()

                self[x.dgst].heuristics.labeled = True

        certs_to_verify: List[CommonCriteriaCert] = [x for x in self if (x.heuristics.cpe_matches and not x.heuristics.labeled)]
        logger.info('Manually verifying CPE matches')
        time.sleep(0.05)  # easier than flushing the logger
        verify_certs(certs_to_verify)

        if update_json is True:
            self.to_json()

    def compute_related_cves(self, download_fresh_cves: bool = False):
        logger.info('Retrieving related CVEs to verified CPE matches')
        cve_dset = self.prepare_cve_dataset(download_fresh_cves)

        verified_cpe_rich_certs = [x for x in self if x.heuristics.verified_cpe_matches]
        if not verified_cpe_rich_certs:
            logger.error('No certificates with verified CPE match detected. You must run dset.manually_verify_cpe_matches() first. Returning.')
            return
        for cert in verified_cpe_rich_certs:
            cert.compute_heuristics_related_cves(cve_dset)

    def to_label_studio_json(self, output_path: Union[str, Path]):
        lst = []
        for cert in [x for x in self if x.heuristics.cpe_matches and not x.heuristics.labeled]:
            dct = {'text': cert.name}
            candidates = [x[1].title for x in cert.heuristics.cpe_matches]
            candidates += ['No good match'] * (constants.CPE_MAX_MATCHES - len(candidates))
            options = ['option_' + str(x) for x in range(1, 21)]
            dct.update({o: c for o, c in zip(options, candidates)})
            lst.append(dct)

        with Path(output_path).open('w') as handle:
            json.dump(lst, handle, indent=4)

    def get_certs_from_name(self, cert_name: str) -> List[CommonCriteriaCert]:
        return [crt for crt in self if crt.name == cert_name]

    def load_label_studio_labels(self, input_path: Union[str, Path]):
        with Path(input_path).open('r') as handle:
            data = json.load(handle)

        cpe_dset = self.prepare_cpe_dataset()

        for annotation in data:
            if 'verified_cpe_match' not in annotation:
                continue

            match_keys = annotation['verified_cpe_match']['choices']
            if isinstance(match_keys, str):
                match_keys = [match_keys]
            match_keys = [x[1:] for x in match_keys]
            cpes = itertools.chain.from_iterable([cpe_dset.get_cpes_from_title(annotation[x]) for x in match_keys])
            certs = self.get_certs_from_name(annotation['text'])

            for c in certs:
                c.heuristics.verified_cpe_matches = cpes
