import re
from datetime import datetime, date
from dataclasses import dataclass
import logging
from pathlib import Path
import os
import copy
import json
import requests

from abc import ABC, abstractmethod
from bs4 import Tag, BeautifulSoup, NavigableString
from typing import Union, Optional, List, Dict, ClassVar, TypeVar, Type, Tuple

from tabula import read_pdf

from sec_certs import helpers, extract_certificates, dataset
from sec_certs.serialization import ComplexSerializableType, CustomJSONDecoder, CustomJSONEncoder
import sec_certs.constants as constants
from sec_certs.extract_certificates import load_cert_file, normalize_match_string, save_modified_cert_file, REGEXEC_SEP, \
    LINE_SEPARATOR
from sec_certs.cert_rules import fips_rules


logger = logging.getLogger(__name__)


class Certificate(ABC):
    T = TypeVar('T', bound='Certificate')

    def __init__(self, *args, **kwargs):
        pass

    def __repr__(self) -> str:
        return str(self.to_dict())

    def __str__(self) -> str:
        return 'Not implemented'

    @property
    @abstractmethod
    def dgst(self):
        raise NotImplementedError('Not meant to be implemented')

    def __eq__(self, other: 'Certificate') -> bool:
        return self.dgst == other.dgst

    def to_dict(self):
        return copy.deepcopy(self.__dict__)

    @classmethod
    def from_dict(cls: Type[T], dct: dict) -> T:
        return cls(*tuple(dct.values()))

    def to_json(self, output_path: Union[Path, str]):
        with Path(output_path).open('w') as handle:
            json.dump(self, handle, indent=4, cls=CustomJSONEncoder)

    @classmethod
    def from_json(cls, input_path: Union[Path, str]):
        with Path(input_path).open('r') as handle:
            return json.load(handle, cls=CustomJSONDecoder)


class FIPSCertificate(Certificate, ComplexSerializableType):
    FIPS_BASE_URL: ClassVar[str] = 'https://csrc.nist.gov'
    FIPS_MODULE_URL: ClassVar[
        str] = 'https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/'

    @dataclass(eq=True)
    class State(ComplexSerializableType):

        @classmethod
        def from_dict(cls, dct: Dict):
            return cls(Path(dct['sp_path']), Path(dct['html_path']), Path(dct['fragment_path']))

        def to_dict(self):
            return self.__dict__

        sp_path: Path
        html_path: Path
        fragment_path: Path

    @dataclass(eq=True, frozen=True)
    class Algorithm(ComplexSerializableType):
        cert_id: str
        vendor: str
        implementation: str
        type: str
        date: str

        @property
        def dgst(self):
            # certs in dataset are in format { id: [FIPSAlgorithm] }, there is only one type of algorithm
            # for each id
            return self.type

        def __repr__(self):
            return self.type + ' algorithm #' + self.cert_id + ' created by ' + self.vendor

        def __str__(self):
            return str(self.type + ' algorithm #' + self.cert_id + ' created by ' + self.vendor)

        def to_dict(self):
            return copy.deepcopy(self.__dict__)

        @classmethod
        def from_dict(cls, dct: dict) -> 'FIPSCertificate.Algorithm':
            return cls(dct['cert_id'], dct['vendor'], dct['implementation'], dct['type'],
                       dct['date'])

    def __str__(self) -> str:
        return str(self.cert_id)

    @property
    def dgst(self) -> str:
        return self.cert_id

    @staticmethod
    def download_security_policy(cert: Tuple[str, Path]) -> None:
        exit_code = helpers.download_file(*cert)
        if exit_code != requests.codes.ok:
            logger.error(f'Failed to download security policy from {cert[0]}, code: {exit_code}')

    def __init__(self, cert_id: str,
                 module_name: Optional[str],
                 standard: Optional[str],
                 status: Optional[str],
                 date_sunset: Optional[List[str]],
                 date_validation: Optional[List[str]],
                 level: Optional[str],
                 caveat: Optional[str],
                 exceptions: Optional[List[str]],
                 module_type: Optional[str],
                 embodiment: Optional[str],
                 algorithms: Optional[List[Dict[str, str]]],
                 tested_conf: Optional[List[str]],
                 description: Optional[str],
                 mentioned_certs: Optional[List[str]],
                 vendor: Optional[str],
                 vendor_www: Optional[str],
                 lab: Optional[str],
                 lab_nvlap: Optional[str],
                 historical_reason: Optional[str],
                 security_policy_www: Optional[str],
                 certificate_www: Optional[str],
                 hw_version: Optional[str],
                 fw_version: Optional[str],
                 tables: bool,
                 file_status: Optional[bool],
                 connections: List,
                 state: State,
                 txt_state: bool,
                 keywords: Dict,
                 revoked_reason: Optional[str],
                 revoked_link: Optional[str]):
        super().__init__()
        self.cert_id = cert_id

        self.module_name = module_name
        self.standard = standard
        self.status = status
        self.date_sunset = date_sunset
        self.date_validation = date_validation
        self.level = level
        self.caveat = caveat
        self.exceptions = exceptions
        self.type = module_type
        self.embodiment = embodiment

        self.algorithms = algorithms
        self.tested_conf = tested_conf
        self.description = description
        self.mentioned_certs = mentioned_certs
        self.vendor = vendor
        self.vendor_www = vendor_www
        self.lab = lab
        self.lab_nvlap = lab_nvlap

        self.historical_reason = historical_reason

        self.security_policy_www = security_policy_www
        self.certificate_www = certificate_www
        self.hw_versions = hw_version
        self.fw_versions = fw_version

        self.tables_done = tables
        self.file_status = file_status
        self.connections = connections
        self.state = state
        self.txt_state = txt_state
        self.keywords = keywords

        self.revoked_reason = revoked_reason
        self.revoked_link = revoked_link

    @staticmethod
    def download_html_page(cert: Tuple[str, Path]) -> None:
        exit_code = helpers.download_file(*cert)
        if exit_code != requests.codes.ok:
            logger.error(f'Failed to download html page from {cert[0]}, code: {exit_code}')

    @staticmethod
    def extract_filename(file: str) -> str:
        """
        Extracts filename from path
        @param file: UN*X path
        :return: filename without last extension
        """
        return os.path.splitext(os.path.basename(file))[0]

    @staticmethod
    def initialize_dictionary() -> Dict:
        d = {'module_name': None, 'standard': None, 'status': None, 'date_sunset': None,
             'date_validation': None, 'level': None, 'caveat': None, 'exceptions': None,
             'type': None, 'embodiment': None, 'tested_conf': None, 'description': None,
             'vendor': None, 'vendor_www': None, 'lab': None, 'lab_nvlap': None,
             'historical_reason': None, 'revoked_reason': None, 'revoked_link': None, 'algorithms': [],
             'mentioned_certs': [], 'tables_done': False, 'security_policy_www': None, 'certificate_www': None,
             'hw_versions': None, 'fw_versions': None}

        return d

    @staticmethod
    def parse_caveat(current_text: str) -> List:
        """
        Parses content of "Caveat" of FIPS CMVP .html file
        :param current_text: text of "Caveat"
        :return: list of all found algorithm IDs
        """
        ids_found = []
        r_key = r"(?:#\s?|Cert\.?(?!.\s)\s?|Certificate\s?)(?P<id>\d+)"
        for m in re.finditer(r_key, current_text):
            if r_key in ids_found and m.group() in ids_found[0]:
                ids_found[0][m.group()]['count'] += 1
            else:
                ids_found.append(
                    {r"(?:#\s?|Cert\.?(?!.\s)\s?|Certificate\s?)(?P<id>\d+?})": {m.group(): {'count': 1}}})

        return ids_found

    @staticmethod
    def extract_algorithm_certificates(current_text: str, in_pdf: bool = False) -> List:
        """
        Parses table of FIPS (non) allowed algorithms
        :param current_text: Contents of the table
        :param in_pdf: Specifies whether the table was found in a PDF security policies file
        :return: List containing one element - dictionary with all parsed algorithm cert ids
        """
        set_items = set()
        for m in re.finditer(
                rf"(?:#{'?' if in_pdf else '[CcAa]?'}\s?|(?:Cert{'' if in_pdf else '?'})\.?[^. ]*?\s?)(?:[CcAa]\s)?(?P<id>\d+)",
                current_text):
            set_items.add(m.group())

        return [{"Certificate": list(set_items)}]

    @staticmethod
    def parse_table(element: Union[Tag, NavigableString]) -> List[Dict]:
        """
        Parses content of <table> tags in FIPS .html CMVP page
        :param element: text in <table> tags
        :return: list of all found algorithm IDs
        """
        found_items = []
        trs = element.find_all('tr')
        for tr in trs:
            tds = tr.find_all('td')
            found_items.append(
                {'Name': tds[0].text, 'Certificate': FIPSCertificate.extract_algorithm_certificates(tds[1].text)[0]['Certificate']})

        return found_items

    @staticmethod
    def parse_html_main(current_div: Tag, html_items_found: Dict, pairs: Dict):
        title = current_div.find('div', class_='col-md-3').text.strip()
        content = current_div.find('div', class_='col-md-9').text.strip() \
            .replace('\n', '').replace('\t', '').replace('    ', ' ')

        if title in pairs:
            if 'date' in pairs[title]:
                html_items_found[pairs[title]] = content.split(';')
            elif 'caveat' in pairs[title]:
                html_items_found[pairs[title]] = content
                html_items_found['mentioned_certs'] += FIPSCertificate.parse_caveat(
                    content)

            elif 'FIPS Algorithms' in title:
                html_items_found['algorithms'] += FIPSCertificate.parse_table(
                    current_div.find('div', class_='col-md-9'))

            elif 'Algorithms' in title or 'Description' in title:
                html_items_found['algorithms'] += FIPSCertificate.extract_algorithm_certificates(content)

            elif 'tested_conf' in pairs[title]:
                html_items_found[pairs[title]] = [x.text for x in
                                                  current_div.find('div', class_='col-md-9').find_all('li')]
            else:
                html_items_found[pairs[title]] = content

    @staticmethod
    def parse_vendor(current_div: Tag, html_items_found: Dict, current_file: Path):
        vendor_string = current_div.find('div', 'panel-body').find('a')

        if not vendor_string:
            vendor_string = list(current_div.find(
                'div', 'panel-body').children)[0].strip()
            html_items_found['vendor_www'] = ''
        else:
            html_items_found['vendor_www'] = vendor_string.get('href')
            vendor_string = vendor_string.text.strip()

        html_items_found['vendor'] = vendor_string
        if html_items_found['vendor'] == '':
            logger.warning(f"WARNING: NO VENDOR FOUND {current_file}")

    @staticmethod
    def parse_lab(current_div: Tag, html_items_found: Dict, current_file: Path):
        html_items_found['lab'] = list(
            current_div.find('div', 'panel-body').children)[0].strip()
        html_items_found['nvlap_code'] = \
            list(current_div.find(
                'div', 'panel-body').children)[2].strip().split('\n')[1].strip()

        if html_items_found['lab'] == '':
            logger.warning(f"WARNING: NO LAB FOUND {current_file}")

        if html_items_found['nvlap_code'] == '':
            logger.warning(f"WARNING: NO NVLAP CODE FOUND {current_file}")

    @staticmethod
    def parse_related_files(current_div: Tag, html_items_found: Dict):
        links = current_div.find_all('a')
        html_items_found['security_policy_www'] = dataset.FIPSDataset.FIPS_BASE_URL + links[0].get('href')

        if len(links) == 2:
            html_items_found['certificate_www'] = dataset.FIPSDataset.FIPS_BASE_URL + links[1].get('href')

    @classmethod
    def html_from_file(cls, file: Path, state: State, initialized: 'FIPSCertificate' = None) -> 'FIPSCertificate':
        pairs = {
            'Module Name': 'module_name',
            'Standard': 'standard',
            'Status': 'status',
            'Sunset Date': 'date_sunset',
            'Validation Dates': 'date_validation',
            'Overall Level': 'level',
            'Caveat': 'caveat',
            'Security Level Exceptions': 'exceptions',
            'Module Type': 'type',
            'Embodiment': 'embodiment',
            'FIPS Algorithms': 'algorithms',
            'Allowed Algorithms': 'algorithms',
            'Other Algorithms': 'algorithms',
            'Tested Configuration(s)': 'tested_conf',
            'Description': 'description',
            'Historical Reason': 'historical_reason',
            'Hardware Versions': 'hw_versions',
            'Firmware Versions': 'fw_versions',
            'Revoked Reason': 'revoked_reason',
            'Revoked Link': 'revoked_link'
        }
        if not initialized:
            items_found = FIPSCertificate.initialize_dictionary()
            items_found['cert_id'] = file.stem

        else:
            items_found = initialized.__dict__
            items_found['revoked_reason'] = None
            items_found['revoked_link'] = None

        text = extract_certificates.load_cert_html_file(file)
        soup = BeautifulSoup(text, 'html.parser')
        for div in soup.find_all('div', class_='row padrow'):
            FIPSCertificate.parse_html_main(div, items_found, pairs)

        for div in soup.find_all('div', class_='panel panel-default')[1:]:
            if div.find('h4', class_='panel-title').text == 'Vendor':
                FIPSCertificate.parse_vendor(div, items_found, file)

            if div.find('h4', class_='panel-title').text == 'Lab':
                FIPSCertificate.parse_lab(div, items_found, file)

            if div.find('h4', class_='panel-title').text == 'Related Files':
                FIPSCertificate.parse_related_files(div, items_found)

        if initialized:
            new_algs = []
            not_defined = set()
            for i, alg in enumerate(items_found['algorithms']):
                if 'Name' not in alg:
                    for cert_id in alg['Certificate']:
                        not_defined.add(cert_id)
                    continue
                for pair in range(i + 1, len(items_found['algorithms'])):
                    if 'Name' in items_found['algorithms'][pair] \
                            and alg['Name'] == items_found['algorithms'][pair]['Name']:
                        entry = {'Name': alg['Name'], 'Certificate':
                            list(set([x for x in alg['Certificate']]) | set(items_found['algorithms'][pair]['Certificate']))}
                        if entry not in new_algs:
                            new_algs.append(entry)
            for entry in new_algs:
                if entry['Name'] == 'Not Defined':
                    entry['Certificate'] = list(set(entry['Certificate'] | not_defined))
                    break
            else:
                new_algs.append({'Name': 'Not Defined', 'Certificate': list(not_defined)})

            items_found['algorithms'] = new_algs

        return FIPSCertificate(items_found['cert_id'],
                               items_found['module_name'],
                               items_found['standard'],
                               items_found['status'],
                               items_found['date_sunset'],
                               items_found['date_validation'],
                               items_found['level'],
                               items_found['caveat'],
                               items_found['exceptions'],
                               items_found['type'],
                               items_found['embodiment'],
                               items_found['algorithms'],
                               items_found['tested_conf'],
                               items_found['description'],
                               items_found['mentioned_certs'],
                               items_found['vendor'],
                               items_found['vendor_www'],
                               items_found['lab'],
                               items_found['nvlap_code'],
                               items_found['historical_reason'],
                               items_found['security_policy_www'],
                               items_found['certificate_www'],
                               items_found['hw_versions'],
                               items_found['fw_versions'],
                               False if not initialized else items_found['tables_done'],
                               None,
                               [],
                               state,
                               False if not initialized else items_found['txt_state'],
                               None if not initialized else items_found['keywords'],
                               items_found['revoked_reason'],
                               items_found['revoked_link'])

    @staticmethod
    def convert_pdf_file(tup: Tuple['FIPSCertificate', Path, Path]) -> 'FIPSCertificate':
        cert, pdf_path, txt_path = tup
        if not cert.txt_state:
            exit_code = helpers.convert_pdf_file(pdf_path, txt_path, ['-raw'])
            if exit_code != constants.RETURNCODE_OK:
                logger.error(f'Cert dgst: {cert.dgst} failed to convert security policy pdf->txt')
                cert.txt_state = False
            else:
                cert.txt_state = True
        return cert

    @staticmethod
    def parse_cert_file(cert: 'FIPSCertificate') -> Tuple[Optional[Dict], 'FIPSCertificate']:
        if not cert.txt_state:
            return None, cert

        _, whole_text_with_newlines, unicode_error = load_cert_file(cert.state.sp_path.with_suffix('.pdf.txt'), -1,
                                                                    LINE_SEPARATOR)

        # apply all rules
        items_found_all = {}
        for rule_group in fips_rules.keys():
            if rule_group not in items_found_all:
                items_found_all[rule_group] = {}

            items_found = items_found_all[rule_group]

            for rule in fips_rules[rule_group]:
                # rule_and_sep = rule + REGEXEC_SEP
                for m in rule.finditer(whole_text_with_newlines):
                # for m in re.finditer(rule, whole_text_with_newlines):
                    # insert rule if at least one match for it was found
                    if rule.pattern not in items_found:
                        items_found[rule.pattern] = {}

                    match = m.group()
                    match = normalize_match_string(match)

                    if match == '':
                        continue

                    certs = [x['Certificate'] for x in cert.algorithms]

                    match_cert_id = ''.join(filter(str.isdigit, match))

                    for fips_cert in certs:
                        for actual_cert in fips_cert:
                            if actual_cert != '' and match_cert_id == ''.join(filter(str.isdigit, actual_cert)):
                                continue

                    if match not in items_found[rule.pattern]:
                        items_found[rule.pattern][match] = {}
                        items_found[rule.pattern][match][constants.TAG_MATCH_COUNTER] = 0

                    items_found[rule.pattern][match][constants.TAG_MATCH_COUNTER] += 1

                    whole_text_with_newlines = whole_text_with_newlines.replace(
                        match, 'x' * len(match))

        save_modified_cert_file(cert.state.fragment_path, whole_text_with_newlines, unicode_error)
        return items_found_all, cert

    @staticmethod
    def analyze_tables(cert: 'FIPSCertificate') -> Tuple[bool, 'FIPSCertificate', List]:
        cert_file = cert.state.sp_path
        txt_file = cert_file.with_suffix('.pdf.txt')
        with open(txt_file, 'r') as f:
            tables = helpers.find_tables(f.read(), txt_file)

        lst = []
        if tables:
            try:
                data = read_pdf(cert_file, pages=tables, silent=True)
            except Exception as e:
                try:
                    logger.error(e)
                    helpers.repair_pdf(cert_file)
                    data = read_pdf(cert_file, pages=tables, silent=True)

                except Exception as ex:
                    logger.error(ex)
                    return False, cert, lst

            # find columns with cert numbers
            for df in data:
                for col in range(len(df.columns)):
                    if 'cert' in df.columns[col].lower() or 'algo' in df.columns[col].lower():
                        lst += FIPSCertificate.extract_algorithm_certificates(
                            df.iloc[:, col].to_string(index=False), True)

                # Parse again if someone picks not so descriptive column names
                lst += FIPSCertificate.extract_algorithm_certificates(df.to_string(index=False))
        return True, cert, lst

    def remove_algorithms(self):
        self.file_status = True
        if not self.keywords:
            return

        if self.mentioned_certs:
            for item in self.mentioned_certs:
                self.keywords['rules_cert_id'].update(item)

        for rule in self.keywords['rules_cert_id']:
            to_pop = set()
            rr = re.compile(rule)
            for cert in self.keywords['rules_cert_id'][rule]:
                for alg in self.keywords['rules_fips_algorithms']:
                    for found in self.keywords['rules_fips_algorithms'][alg]:
                        if rr.search(found) \
                                and rr.search(cert) \
                                and rr.search(found).group('id') == rr.search(cert).group('id'):
                            to_pop.add(cert)
            for r in to_pop:
                self.keywords['rules_cert_id'][rule].pop(r, None)

            self.keywords['rules_cert_id'][rule].pop(self.cert_id, None)


class CommonCriteriaCert(Certificate, ComplexSerializableType):
    cc_url = 'http://www.commoncriteriaportal.org'
    empty_st_url = 'http://www.commoncriteriaportal.org/files/epfiles/'

    @dataclass(eq=True, frozen=True)
    class MaintainanceReport(ComplexSerializableType):
        """
        Object for holding maintainance reports.
        """
        maintainance_date: date
        maintainance_title: str
        maintainance_report_link: str
        maintainance_st_link: str

        def __post_init__(self):
            super().__setattr__('maintainance_report_link',
                                helpers.sanitize_link(self.maintainance_report_link))
            super().__setattr__('maintainance_st_link',
                                helpers.sanitize_link(self.maintainance_st_link))
            super().__setattr__('maintainance_title',
                                helpers.sanitize_string(self.maintainance_title))
            super().__setattr__('maintainance_date', helpers.sanitize_date(self.maintainance_date))

        def to_dict(self):
            return copy.deepcopy(self.__dict__)

        @classmethod
        def from_dict(cls, dct):
            return cls(*tuple(dct.values()))

        def __lt__(self, other):
            return self.maintainance_date < other.maintainance_date

    @dataclass(eq=True, frozen=True)
    class ProtectionProfile(ComplexSerializableType):
        """
        Object for holding protection profiles.
        """
        pp_name: str
        pp_link: Optional[str]

        def __post_init__(self):
            super().__setattr__('pp_name', helpers.sanitize_string(self.pp_name))
            super().__setattr__('pp_link', helpers.sanitize_link(self.pp_link))

        def to_dict(self):
            return copy.deepcopy(self.__dict__)

        @classmethod
        def from_dict(cls, dct):
            return cls(*tuple(dct.values()))

        def __lt__(self, other):
            return self.pp_name < other.pp_name

    @dataclass(init=False)
    class InternalState(ComplexSerializableType):
        st_link_ok: bool
        report_link_ok: bool
        st_convert_ok: bool
        report_convert_ok: bool
        st_pdf_path: Path
        report_pdf_path: Path
        st_txt_path: Path
        report_txt_path: Path

        def __init__(self, st_link_ok: bool = True, report_link_ok: bool = True,
                     st_convert_ok: bool = True, report_convert_ok: bool = True):
            self.st_link_ok = st_link_ok
            self.report_link_ok = report_link_ok
            self.st_convert_ok = st_convert_ok
            self.report_convert_ok = report_convert_ok

        def to_dict(self):
            return {'st_link_ok': self.st_link_ok, 'report_link_ok': self.report_link_ok,
                    'st_convert_ok': self.st_convert_ok, 'report_convert_ok': self.report_convert_ok}

        @classmethod
        def from_dict(cls, dct: Dict[str, bool]):
            return cls(*tuple(dct.values()))

    def __init__(self, category: str, name: str, manufacturer: str, scheme: str,
                 security_level: Union[str, set], not_valid_before: date,
                 not_valid_after: date, report_link: str, st_link: str, src: str, cert_link: Optional[str],
                 manufacturer_web: Optional[str],
                 protection_profiles: set,
                 maintainance_updates: set,
                 state: Optional[InternalState]):
        super().__init__()

        self.category = category
        self.name = helpers.sanitize_string(name)
        self.manufacturer = helpers.sanitize_string(manufacturer)
        self.scheme = scheme
        self.security_level = helpers.sanitize_security_levels(security_level)
        self.not_valid_before = helpers.sanitize_date(not_valid_before)
        self.not_valid_after = helpers.sanitize_date(not_valid_after)
        self.report_link = helpers.sanitize_link(report_link)
        self.st_link = helpers.sanitize_link(st_link)
        self.src = src
        self.cert_link = helpers.sanitize_link(cert_link)
        self.manufacturer_web = helpers.sanitize_link(manufacturer_web)
        self.protection_profiles = protection_profiles
        self.maintainance_updates = maintainance_updates

        if state is not None:
            self.state = state
        else:
            self.state = self.InternalState()

    @property
    def dgst(self) -> str:
        """
        Computes the primary key of the certificate using first 16 bytes of SHA-256 digest
        """
        return helpers.get_first_16_bytes_sha256(self.category + self.name + self.report_link)

    def merge(self, other: 'CommonCriteriaCert'):
        """
        Merges with other CC certificate. Assuming they come from different sources, e.g., csv and html.
        Assuming that html source has better protection profiles, they overwrite CSV info
        On other values (apart from maintainances, see TODO below) the sanity checks are made.
        """
        if self != other:
            logger.warning(
                f'Attempting to merge divergent certificates: self[dgst]={self.dgst}, other[dgst]={other.dgst}')

        for att, val in vars(self).items():
            if not val:
                setattr(self, att, getattr(other, att))
            elif self.src == 'csv' and other.src == 'html' and att == 'protection_profiles':
                setattr(self, att, getattr(other, att))
            elif self.src == 'csv' and other.src == 'html' and att == 'maintainance_updates':
                # TODO Fix me: This is a simplification. At the moment html contains more reliable info
                setattr(self, att, getattr(other, att))
            elif att == 'src':
                pass  # This is expected
            elif att == 'state':
                setattr(self, att, getattr(other, att))
            else:
                if getattr(self, att) != getattr(other, att):
                    logger.warning(
                        f'When merging certificates with dgst {self.dgst}, the following mismatch occured: Attribute={att}, self[{att}]={getattr(self, att)}, other[{att}]={getattr(other, att)}')
        if self.src != other.src:
            self.src = self.src + ' + ' + other.src

    @classmethod
    def from_dict(cls, dct: Dict) -> 'CommonCriteriaCert':
        new_dct = dct.copy()
        new_dct['maintainance_updates'] = set(dct['maintainance_updates'])
        new_dct['protection_profiles'] = set(dct['protection_profiles'])
        return super(cls, CommonCriteriaCert).from_dict(new_dct)

    @classmethod
    def from_html_row(cls, row: Tag, category: str) -> 'CommonCriteriaCert':
        """
        Creates a CC certificate from html row
        """

        def _get_name(cell: Tag) -> str:
            return list(cell.stripped_strings)[0]

        def _get_manufacturer(cell: Tag) -> Optional[str]:
            if lst := list(cell.stripped_strings):
                return lst[0]
            else:
                return None

        def _get_scheme(cell: Tag) -> str:
            return list(cell.stripped_strings)[0]

        def _get_security_level(cell: Tag) -> set:
            return set(cell.stripped_strings)

        def _get_manufacturer_web(cell: Tag) -> Optional[str]:
            for link in cell.find_all('a'):
                if link is not None and link.get('title') == 'Vendor\'s web site' and link.get('href') != 'http://':
                    return link.get('href')
            return None

        def _get_protection_profiles(cell: Tag) -> set:
            protection_profiles = set()
            for link in list(cell.find_all('a')):
                if link.get('href') is not None and '/ppfiles/' in link.get('href'):
                    protection_profiles.add(CommonCriteriaCert.ProtectionProfile(str(link.contents[0]),
                                                                                 CommonCriteriaCert.cc_url + link.get(
                                                                                     'href')))
            return protection_profiles

        def _get_date(cell: Tag) -> date:
            text = cell.get_text()
            extracted_date = datetime.strptime(
                text, '%Y-%m-%d').date() if text else None
            return extracted_date

        def _get_report_st_links(cell: Tag) -> (str, str):
            links = cell.find_all('a')
            # TODO: Exception checks
            assert links[1].get('title').startswith('Certification Report')
            assert links[2].get('title').startswith('Security Target')

            report_link = CommonCriteriaCert.cc_url + links[1].get('href')
            security_target_link = CommonCriteriaCert.cc_url + \
                                   links[2].get('href')

            return report_link, security_target_link

        def _get_cert_link(cell: Tag) -> Optional[str]:
            links = cell.find_all('a')
            return CommonCriteriaCert.cc_url + links[0].get('href') if links else None

        def _get_maintainance_div(cell: Tag) -> Optional[Tag]:
            divs = cell.find_all('div')
            for d in divs:
                if d.find('div') and d.stripped_strings and list(d.stripped_strings)[0] == 'Maintenance Report(s)':
                    return d
            return None

        def _get_maintainance_updates(main_div: Tag) -> set:
            possible_updates = list(main_div.find_all('li'))
            maintainance_updates = set()
            for u in possible_updates:
                text = list(u.stripped_strings)[0]
                main_date = datetime.strptime(text.split(
                    ' ')[0], '%Y-%m-%d').date() if text else None
                main_title = text.split('– ')[1]
                main_report_link = None
                main_st_link = None
                links = u.find_all('a')
                for l in links:
                    if l.get('title').startswith('Maintenance Report:'):
                        main_report_link = CommonCriteriaCert.cc_url + \
                                           l.get('href')
                    elif l.get('title').startswith('Maintenance ST'):
                        main_st_link = CommonCriteriaCert.cc_url + \
                                       l.get('href')
                    else:
                        logger.error('Unknown link in Maintenance part!')
                maintainance_updates.add(
                    CommonCriteriaCert.MaintainanceReport(main_date, main_title, main_report_link, main_st_link))
            return maintainance_updates

        cells = list(row.find_all('td'))
        if len(cells) != 7:
            logger.error('Unexpected number of cells in CC html row.')
            raise

        name = _get_name(cells[0])
        manufacturer = _get_manufacturer(cells[1])
        manufacturer_web = _get_manufacturer_web(cells[1])
        scheme = _get_scheme(cells[6])
        security_level = _get_security_level(cells[5])
        protection_profiles = _get_protection_profiles(cells[0])
        not_valid_before = _get_date(cells[3])
        not_valid_after = _get_date(cells[4])
        report_link, st_link = _get_report_st_links(cells[0])
        cert_link = _get_cert_link(cells[2])

        maintainance_div = _get_maintainance_div(cells[0])
        maintainances = _get_maintainance_updates(
            maintainance_div) if maintainance_div else set()

        return cls(category, name, manufacturer, scheme, security_level, not_valid_before, not_valid_after, report_link,
                   st_link, 'html', cert_link, manufacturer_web, protection_profiles, maintainances, None)

    def set_local_paths(self,
                        report_pdf_dir: Optional[Union[str, Path]],
                        st_pdf_dir: Optional[Union[str, Path]],
                        report_txt_dir: Optional[Union[str, Path]],
                        st_txt_dir: Optional[Union[str, Path]]):
        if report_pdf_dir is not None:
            self.state.report_pdf_path = Path(report_pdf_dir) / (self.dgst + '.pdf')
        if st_pdf_dir is not None:
            self.state.st_pdf_path = Path(st_pdf_dir) / (self.dgst + '.pdf')
        if report_txt_dir is not None:
            self.state.report_txt_path = Path(report_txt_dir) / (self.dgst + '.txt')
        if st_txt_dir is not None:
            self.state.st_txt_path = Path(st_txt_dir) / (self.dgst + '.txt')

    @staticmethod
    def download_pdf_report(cert: 'CommonCriteriaCert') -> 'CommonCriteriaCert':
        exit_code = helpers.download_file(cert.report_link, cert.state.report_pdf_path)
        if exit_code != requests.codes.ok:
            logger.error(f'Failed to download report from {cert.report_link}, code: {exit_code}')
            cert.state.report_link_ok = False
        return cert

    @staticmethod
    def download_pdf_target(cert: 'CommonCriteriaCert') -> 'CommonCriteriaCert':
        exit_code = helpers.download_file(cert.st_link, cert.state.st_pdf_path)
        if exit_code != requests.codes.ok:
            logger.error(f'Cert dgst: {cert.dgst} failed to download report from {cert.report_link}, code: {exit_code}')
            cert.state.st_link_ok = False
        return cert

    def path_is_corrupted(self, local_path):
        return not local_path.exists() or local_path.stat().st_size < constants.MIN_CORRECT_CERT_SIZE

    @staticmethod
    def convert_report_pdf(cert: 'CommonCriteriaCert') -> 'CommonCriteriaCert':
        exit_code = helpers.convert_pdf_file(cert.state.report_pdf_path, cert.state.report_txt_path, ['-raw'])
        if exit_code != constants.RETURNCODE_OK:
            logger.error(f'Cert dgst: {cert.dgst} failed to convert report pdf->txt')
            cert.state.report_convert_ok = False
        return cert

    @staticmethod
    def convert_target_pdf(cert: 'CommonCriteriaCert') -> 'CommonCriteriaCert':
        exit_code = helpers.convert_pdf_file(cert.state.st_pdf_path, cert.state.st_txt_path, ['-raw'])
        if exit_code != constants.RETURNCODE_OK:
            logger.error(f'Cert dgst: {cert.dgst} failed to convert security target pdf->txt')
            cert.state.st_convert_ok = False
        return cert
