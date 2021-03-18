import re
from datetime import datetime, date
from dataclasses import dataclass
import logging
from pathlib import Path
import os
import copy
import json
import requests
from dateutil import parser

from abc import ABC, abstractmethod
from bs4 import Tag, BeautifulSoup, NavigableString
from typing import Union, Optional, List, Dict, ClassVar, TypeVar, Type, Tuple, Pattern, Set

from tabula import read_pdf

from sec_certs import helpers, extract_certificates, dataset
from sec_certs.serialization import ComplexSerializableType, CustomJSONDecoder, CustomJSONEncoder
import sec_certs.constants as constants
from sec_certs.extract_certificates import load_cert_file, normalize_match_string, save_modified_cert_file, REGEXEC_SEP, \
    LINE_SEPARATOR, APPEND_DETAILED_MATCH_MATCHES
from sec_certs.cert_rules import fips_rules, fips_common_rules
from sec_certs.configuration import config

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
        return {**{'dgst': self.dgst}, **copy.deepcopy(self.__dict__)}

    @classmethod
    def from_dict(cls: Type[T], dct: dict) -> T:
        dct.pop('dgst')
        return cls(*(tuple(dct.values())))

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
            return cls(Path(dct['sp_path']), Path(dct['html_path']), Path(dct['fragment_path']), dct['tables_done'],
                       dct['file_status'], dct['txt_state'])

        def to_dict(self):
            return self.__dict__

        sp_path: Path
        html_path: Path
        fragment_path: Path
        tables_done: bool
        file_status: Optional[bool]
        txt_state: bool

    @dataclass(eq=True)
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

    @dataclass(eq=True)
    class WebScan(ComplexSerializableType):
        module_name: Optional[str]
        standard: Optional[str]
        status: Optional[str]
        date_sunset: Optional[Union[str, datetime]]
        date_validation: Optional[List[Union[str, datetime]]]
        level: Optional[str]
        caveat: Optional[str]
        exceptions: Optional[List[str]]
        module_type: Optional[str]
        embodiment: Optional[str]
        algorithms: Optional[List[Dict[str, str]]]
        tested_conf: Optional[List[str]]
        description: Optional[str]
        mentioned_certs: Optional[List[str]]
        vendor: Optional[str]
        vendor_www: Optional[str]
        lab: Optional[str]
        lab_nvlap: Optional[str]
        historical_reason: Optional[str]
        security_policy_www: Optional[str]
        certificate_www: Optional[str]
        hw_version: Optional[str]
        fw_version: Optional[str]
        revoked_reason: Optional[str]
        revoked_link: Optional[str]
        sw_versions: Optional[str]
        product_url: Optional[str]

        def __post_init__(self):
            self.date_validation = [parser.parse(x).date() for x in
                                    self.date_validation] if self.date_validation else None
            self.date_sunset = parser.parse(self.date_sunset).date() if self.date_sunset else None

        @property
        def dgst(self):
            # certs in dataset are in format { id: [FIPSAlgorithm] }, there is only one type of algorithm
            # for each id
            return helpers.get_first_16_bytes_sha256(self.product_url + self.vendor_www)

        def __repr__(self):
            return self.module_name + ' created by ' + self.vendor

        def __str__(self):
            return str(self.module_name + ' created by ' + self.vendor)

        def to_dict(self):
            return copy.deepcopy(self.__dict__)

        @classmethod
        def from_dict(cls, dct: dict) -> 'FIPSCertificate.WebScan':
            return cls(*tuple(dct.values()))

    @dataclass(eq=True)
    class PdfScan(ComplexSerializableType):
        cert_id: int
        keywords: Dict
        algorithms: List

        @property
        def dgst(self):
            # certs in dataset are in format { id: [FIPSAlgorithm] }, there is only one type of algorithm
            # for each id
            return helpers.get_first_16_bytes_sha256(str(self.keywords))

        def __repr__(self):
            return self.cert_id

        def __str__(self):
            return str(self.cert_id)

        def to_dict(self):
            return copy.deepcopy(self.__dict__)

        @classmethod
        def from_dict(cls, dct: dict) -> 'FIPSCertificate.PdfScan':
            return cls(*tuple(dct.values()))

    @dataclass(eq=True)
    class Processed(ComplexSerializableType):
        keywords: Optional[Dict]
        algorithms: Dict
        connections: List

        @property
        def dgst(self):
            # certs in dataset are in format { id: [FIPSAlgorithm] }, there is only one type of algorithm
            # for each id
            return helpers.get_first_16_bytes_sha256(str(self.keywords))

        def to_dict(self):
            return copy.deepcopy(self.__dict__)

        @classmethod
        def from_dict(cls, dct: dict) -> 'FIPSCertificate.Processed':
            return cls(*tuple(dct.values()))

    def __str__(self) -> str:
        return str(self.cert_id)

    def to_dict(self) -> Dict:
        return self.__dict__

    @property
    def dgst(self) -> str:
        return self.cert_id

    @staticmethod
    def download_security_policy(cert: Tuple[str, Path]) -> None:
        exit_code = helpers.download_file(*cert)
        if exit_code != requests.codes.ok:
            logger.error(f'Failed to download security policy from {cert[0]}, code: {exit_code}')

    @classmethod
    def from_dict(cls, dct: dict):
        return cls(*tuple(dct.values()))

    def __init__(self, cert_id: str,
                 web_scan: 'FIPSCertificate.WebScan',
                 pdf_scan: 'FIPSCertificate.PdfScan',
                 processed: 'FIPSCertificate.Processed',
                 state: State):
        super().__init__()
        self.cert_id = cert_id
        self.web_scan = web_scan
        self.pdf_scan = pdf_scan
        self.processed = processed
        self.state = state

    @staticmethod
    def download_html_page(cert: Tuple[str, Path]) -> Optional[Tuple[str, Path]]:
        exit_code = helpers.download_file(*cert)
        if exit_code != requests.codes.ok:
            logger.error(f'Failed to download html page from {cert[0]}, code: {exit_code}')
            return cert
        return None

    @staticmethod
    def initialize_dictionary() -> Dict:
        d = {'module_name': None, 'standard': None, 'status': None, 'date_sunset': None,
             'date_validation': None, 'level': None, 'caveat': None, 'exceptions': None,
             'type': None, 'embodiment': None, 'tested_conf': None, 'description': None,
             'vendor': None, 'vendor_www': None, 'lab': None, 'lab_nvlap': None,
             'historical_reason': None, 'revoked_reason': None, 'revoked_link': None, 'algorithms': [],
             'mentioned_certs': [], 'tables_done': False, 'security_policy_www': None, 'certificate_www': None,
             'hw_versions': None, 'fw_versions': None, 'sw_versions': None, 'product_url': None}

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
        if in_pdf:
            reg = r"(?:#?\s?|(?:Cert)\.?[^. ]*?\s?)(?:[CcAa]\s)?(?P<id>[CcAa]? ?\d+)"
        else:
            reg = r"(?:#[CcAa]?\s?|(?:Cert)\.?[^. ]*?\s?)(?:[CcAa]\s)?(?P<id>\d+)"
        for m in re.finditer(reg, current_text):
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
                {'Name': tds[0].text,
                 'Certificate': FIPSCertificate.extract_algorithm_certificates(tds[1].text)[0]['Certificate'],
                 'Links': [str(x) for x in tds[1].find_all('a')],
                 'Raw': str(tr)})

        return found_items

    @staticmethod
    def parse_html_main(current_div: Tag, html_items_found: Dict, pairs: Dict):
        title = current_div.find('div', class_='col-md-3').text.strip()
        content = current_div.find('div', class_='col-md-9').text.strip() \
            .replace('\n', '').replace('\t', '').replace('    ', ' ')

        if title in pairs:
            if 'date_validation' == pairs[title]:
                html_items_found[pairs[title]] = [x for x in content.split(';')]

            elif 'caveat' in pairs[title]:
                html_items_found[pairs[title]] = content
                html_items_found['mentioned_certs'] += FIPSCertificate.parse_caveat(
                    content)

            elif 'FIPS Algorithms' in title:
                html_items_found['algorithms'] += FIPSCertificate.parse_table(
                    current_div.find('div', class_='col-md-9'))

            elif 'Algorithms' in title or 'Description' in title:
                html_items_found['algorithms'] += FIPSCertificate.extract_algorithm_certificates(content)
                if 'Description' in title:
                    html_items_found['description'] = content

            elif 'tested_conf' in pairs[title] or 'exceptions' in pairs[title]:
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

    @staticmethod
    def normalize(items: Dict):
        items['type'] = items['type'].lower().replace('-', ' ').title()
        items['embodiment'] = items['embodiment'].lower().replace('-', ' ').replace('stand alone', 'standalone').title()

    @classmethod
    def html_from_file(cls, file: Path, state: State, initialized: 'FIPSCertificate' = None,
                       redo: bool = False) -> 'FIPSCertificate':
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
            'Revoked Link': 'revoked_link',
            'Software Versions': 'sw_versions',
            'Product URL': 'product_url'
        }
        if not initialized:
            items_found = FIPSCertificate.initialize_dictionary()
            items_found['cert_id'] = file.stem
        else:
            items_found = initialized.web_scan.__dict__
            items_found['cert_id'] = initialized.cert_id
            items_found['revoked_reason'] = None
            items_found['revoked_link'] = None
            items_found['mentioned_certs'] = []
            state.tables_done = initialized.state.tables_done
            state.file_status = initialized.state.file_status
            state.txt_state = initialized.state.txt_state
            initialized.processed.connections = []

        if redo:
            items_found = FIPSCertificate.initialize_dictionary()
            items_found['cert_id'] = file.stem

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

        FIPSCertificate.normalize(items_found)

        return FIPSCertificate(items_found['cert_id'],
                               FIPSCertificate.WebScan(
                                   items_found['module_name'] if 'module_name' in items_found else None,
                                   items_found['standard'] if 'standard' in items_found else None,
                                   items_found['status'] if 'status' in items_found else None,
                                   items_found['date_sunset'] if 'date_sunset' in items_found else None,
                                   items_found['date_validation'] if 'date_validation' in items_found else None,
                                   items_found['level'] if 'level' in items_found else None,
                                   items_found['caveat'] if 'caveat' in items_found else None,
                                   items_found['exceptions'] if 'exceptions' in items_found else None,
                                   items_found['type'] if 'type' in items_found else None,
                                   items_found['embodiment'] if 'embodiment' in items_found else None,
                                   items_found['algorithms'] if 'algorithms' in items_found else None,
                                   items_found['tested_conf'] if 'tested_conf' in items_found else None,
                                   items_found['description'] if 'description' in items_found else None,
                                   items_found['mentioned_certs'] if 'mentioned_certs' in items_found else None,
                                   items_found['vendor'] if 'vendor' in items_found else None,
                                   items_found['vendor_www'] if 'vendor_www' in items_found else None,
                                   items_found['lab'] if 'lab' in items_found else None,
                                   items_found['nvlap_code'] if 'nvlap_code' in items_found else None,
                                   items_found['historical_reason'] if 'historical_reason' in items_found else None,
                                   items_found['security_policy_www'] if 'security_policy_www' in items_found else None,
                                   items_found['certificate_www'] if 'certificate_www' in items_found else None,
                                   items_found['hw_versions'] if 'hw_versions' in items_found else None,
                                   items_found['fw_versions'] if 'fw_versions' in items_found else None,
                                   items_found['revoked_reason'] if 'revoked_reason' in items_found else None,
                                   items_found['revoked_link'] if 'revoked_link' in items_found else None,
                                   items_found['sw_versions'] if 'sw_versions' in items_found else None,
                                   items_found['product_url']) if 'product_url' in items_found else None,
                               FIPSCertificate.PdfScan(
                                   items_found['cert_id'],
                                   {} if not initialized else initialized.pdf_scan.keywords,
                                   [] if not initialized else initialized.pdf_scan.algorithms
                               ),
                               FIPSCertificate.Processed(None, {}, []),
                               state
                               )

    @staticmethod
    def convert_pdf_file(tup: Tuple['FIPSCertificate', Path, Path]) -> 'FIPSCertificate':
        cert, pdf_path, txt_path = tup
        if not cert.state.txt_state:
            exit_code = helpers.convert_pdf_file(pdf_path, txt_path, ['-raw'])
            if exit_code != constants.RETURNCODE_OK:
                logger.error(f'Cert dgst: {cert.dgst} failed to convert security policy pdf->txt')
                cert.state.txt_state = False
            else:
                cert.state.txt_state = True
        return cert

    @staticmethod
    def find_keywords(cert: 'FIPSCertificate') -> Tuple[Optional[Dict], 'FIPSCertificate']:
        if not cert.state.txt_state:
            return None, cert

        text, text_with_newlines, unicode_error = load_cert_file(cert.state.sp_path.with_suffix('.pdf.txt'),
                                                                 -1, LINE_SEPARATOR)

        text_to_parse = text_with_newlines if config.use_text_with_newlines_during_parsing['value'] else text

        items_found, fips_text = FIPSCertificate.parse_cert_file(FIPSCertificate.remove_platforms(text_to_parse),
                                                                 cert.web_scan.algorithms)

        save_modified_cert_file(cert.state.fragment_path.with_suffix('.fips.txt'), fips_text, unicode_error)

        common_items_found, common_text = FIPSCertificate.parse_cert_file_common(text_to_parse, text_with_newlines,
                                                                                 fips_common_rules)

        save_modified_cert_file(cert.state.fragment_path.with_suffix('.common.txt'), common_text, unicode_error)
        items_found.update(common_items_found)

        return items_found, cert

    @staticmethod
    def match_web_algs_to_pdf(cert: 'FIPSCertificate') -> int:
        algs_vals = list(cert.pdf_scan.keywords['rules_fips_algorithms'].values())
        table_vals = [x['Certificate'] for x in cert.pdf_scan.algorithms]
        tables = [x.strip() for y in table_vals for x in y]
        iterable = [l for x in algs_vals for l in list(x.keys())]
        iterable += tables
        all_algorithms = set()
        for x in iterable:
            if '#' in x:
                # erase everything until "#" included and take digits
                all_algorithms.add(''.join(filter(str.isdigit, x[x.index('#') + 1:])))
            else:
                all_algorithms.add(''.join(filter(str.isdigit, x)))
        not_found = []
        for alg_list in (a['Certificate'] for a in cert.web_scan.algorithms):
            for web_alg in alg_list:
                if ''.join(filter(str.isdigit, web_alg)) not in all_algorithms:
                    not_found.append(web_alg)
        logger.error(
            f"For cert {cert.dgst}:\n\tNOT FOUND: {len(not_found)}\n"
            f"\tFOUND: {sum([len(a['Certificate']) for a in cert.web_scan.algorithms]) - len(not_found)}")
        logger.error(f"Not found: {not_found}")
        return len(not_found)

    @staticmethod
    def remove_platforms(text_to_parse: str):
        pat = re.compile(r"(?:modification|revision|change) history\n[\s\S]*?", re.IGNORECASE)
        for match in pat.finditer(text_to_parse):
            text_to_parse = text_to_parse.replace(
                match.group(), 'x' * len(match.group()))
        return text_to_parse

    @staticmethod
    def parse_cert_file_common(text_to_parse: str, whole_text_with_newlines: str,
                               search_rules: Dict) -> Tuple[Optional[Dict], str]:
        # apply all rules
        items_found_all = {}
        for rule_group in search_rules.keys():
            if rule_group not in items_found_all:
                items_found_all[rule_group] = {}

            items_found = items_found_all[rule_group]

            for rule in search_rules[rule_group]:
                if type(rule) != str:
                    rule_str = rule.pattern
                    rule_and_sep = re.compile(rule.pattern + REGEXEC_SEP)
                else:
                    rule_str = rule
                    rule_and_sep = rule + REGEXEC_SEP

                for m in re.finditer(rule_and_sep, text_to_parse):
                    # insert rule if at least one match for it was found
                    if rule not in items_found:
                        items_found[rule_str] = {}

                    match = m.group()
                    match = normalize_match_string(match)

                    MAX_ALLOWED_MATCH_LENGTH = 300
                    match_len = len(match)
                    if match_len > MAX_ALLOWED_MATCH_LENGTH:
                        print('WARNING: Excessive match with length of {} detected for rule {}'.format(match_len, rule))

                    if match not in items_found[rule_str]:
                        items_found[rule_str][match] = {}
                        items_found[rule_str][match][constants.TAG_MATCH_COUNTER] = 0
                        if extract_certificates.APPEND_DETAILED_MATCH_MATCHES:
                            items_found[rule_str][match][constants.TAG_MATCH_MATCHES] = []
                        # else:
                        #     items_found[rule_str][match][TAG_MATCH_MATCHES] = ['List of matches positions disabled. Set APPEND_DETAILED_MATCH_MATCHES to True']

                    items_found[rule_str][match][constants.TAG_MATCH_COUNTER] += 1
                    match_span = m.span()
                    # estimate line in original text file
                    # line_number = get_line_number(lines, line_length_compensation, match_span[0])
                    # start index, end index, line number
                    # items_found[rule_str][match][TAG_MATCH_MATCHES].append([match_span[0], match_span[1], line_number])
                    if extract_certificates.APPEND_DETAILED_MATCH_MATCHES:
                        items_found[rule_str][match][constants.TAG_MATCH_MATCHES].append(
                            [match_span[0], match_span[1]])

        # highlight all found strings (by xxxxx) from the input text and store the rest
        all_matches = []
        for rule_group in items_found_all.keys():
            items_found = items_found_all[rule_group]
            for rule in items_found.keys():
                for match in items_found[rule]:
                    all_matches.append(match)

            # if AES string is removed before AES-128, -128 would be left in text => sort by length first
            # sort before replacement based on the length of match
            all_matches.sort(key=len, reverse=True)
            for match in all_matches:
                whole_text_with_newlines = whole_text_with_newlines.replace(
                    match, 'x' * len(match))

        return items_found_all, whole_text_with_newlines

    @staticmethod
    def parse_cert_file(text_to_parse: str, algorithms: List[Dict]) \
            -> Tuple[Optional[Dict], str]:
        # apply all rules
        items_found_all: Dict = {}
        for rule_group in fips_rules.keys():
            if rule_group not in items_found_all:
                items_found_all[rule_group] = {}

            items_found: Dict[str, Dict] = items_found_all[rule_group]

            for rule in fips_rules[rule_group]:
                for m in rule.finditer(text_to_parse):
                    # for m in re.finditer(rule, whole_text_with_newlines):
                    # insert rule if at least one match for it was found
                    if rule.pattern not in items_found:
                        items_found[rule.pattern] = {}

                    match = m.group()
                    match = normalize_match_string(match)

                    if match == '':
                        continue

                    if match not in items_found[rule.pattern]:
                        items_found[rule.pattern][match] = {}
                        items_found[rule.pattern][match][constants.TAG_MATCH_COUNTER] = 0

                    items_found[rule.pattern][match][constants.TAG_MATCH_COUNTER] += 1

                    text_to_parse = text_to_parse.replace(
                        match, 'x' * len(match))

        return items_found_all, text_to_parse

    @staticmethod
    def analyze_tables(cert: 'FIPSCertificate') -> Tuple[bool, 'FIPSCertificate', List]:
        cert_file = cert.state.sp_path
        txt_file = cert_file.with_suffix('.pdf.txt')
        with open(txt_file, 'r', encoding='utf-8') as f:
            tables = helpers.find_tables(f.read(), txt_file)

        lst: List = []
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

    def _create_alg_set(self) -> Set:
        result = set()
        for alg in self.web_scan.algorithms:
            result.update(cert for cert in alg['Certificate'])
        return result

    def remove_algorithms(self):
        self.state.file_status = True
        if not self.pdf_scan.keywords:
            return

        self.processed.keywords = copy.deepcopy(self.pdf_scan.keywords)
        if self.web_scan.mentioned_certs:
            for item in self.web_scan.mentioned_certs:
                self.processed.keywords['rules_cert_id'].update(item)

        alg_set = self._create_alg_set()

        for rule in self.processed.keywords['rules_cert_id']:
            to_pop = set()
            rr = re.compile(rule)
            for cert in self.processed.keywords['rules_cert_id'][rule]:
                if cert in alg_set:
                    to_pop.add(cert)
                    continue
                for alg in self.processed.keywords['rules_fips_algorithms']:
                    for found in self.processed.keywords['rules_fips_algorithms'][alg]:
                        if rr.search(found) \
                                and rr.search(cert) \
                                and rr.search(found).group('id') == rr.search(cert).group('id'):
                            to_pop.add(cert)

                for alg_cert in self.processed.algorithms:
                    for cert_no in alg_cert['Certificate']:
                        if int(''.join(filter(str.isdigit, cert_no))) == int(''.join(filter(str.isdigit, cert))):
                            to_pop.add(cert)
            for r in to_pop:
                self.processed.keywords['rules_cert_id'][rule].pop(r, None)

            self.processed.keywords['rules_cert_id'][rule].pop(self.cert_id, None)

    @staticmethod
    def get_compare(vendor: str):
        vendor_split = vendor.replace(',', '') \
            .replace('-', ' ').replace('+', ' ').replace('®', '').split()
        return vendor_split[0] if len(vendor_split) > 0 else vendor


class CommonCriteriaCert(Certificate, ComplexSerializableType):
    cc_url = 'http://commoncriteriaportal.org'
    empty_st_url = 'http://commoncriteriaportal.org/files/epfiles/'

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
        st_extract_ok: bool
        report_extract_ok: bool
        st_pdf_path: Path
        report_pdf_path: Path
        st_txt_path: Path
        report_txt_path: Path
        errors: Optional[List[str]]

        def __init__(self, st_link_ok: bool = True, report_link_ok: bool = True,
                     st_convert_ok: bool = True, report_convert_ok: bool = True,
                     st_extract_ok: bool = True, report_extract_ok: bool = True,
                     errors: Optional[List[str]] = None):
            self.st_link_ok = st_link_ok
            self.report_link_ok = report_link_ok
            self.st_convert_ok = st_convert_ok
            self.report_convert_ok = report_convert_ok
            self.st_extract_ok = st_extract_ok
            self.report_extract_ok = report_extract_ok

            if errors is None:
                self.errors = []
            else:
                self.errors = errors

        def to_dict(self):
            return {'st_link_ok': self.st_link_ok, 'report_link_ok': self.report_link_ok,
                    'st_convert_ok': self.st_convert_ok, 'report_convert_ok': self.report_convert_ok,
                    'st_extract_ok': self.st_extract_ok, 'report_extract_ok': self.report_extract_ok,
                    'errors': self.errors}

        @classmethod
        def from_dict(cls, dct: Dict[str, bool]):
            return cls(*tuple(dct.values()))

    @dataclass(init=False)
    class PdfData(ComplexSerializableType):
        report_metadata: Dict[str, str]
        st_metadata: Dict[str, str]
        report_frontpage: Dict[str, str]
        st_frontpage: Dict[str, str]
        report_keywords: Dict[str, str]
        st_keywords: Dict[str, str]

        def __init__(self, report_metadata: Optional[Dict[str, str]] = None,
                     st_metadata: Optional[Dict[str, str]] = None,
                     report_frontpage: Optional[Dict[str, str]] = None, st_frontpage: Optional[Dict[str, str]] = None,
                     report_keywords: Optional[Dict[str, str]] = None, st_keywords: Optional[Dict[str, str]] = None):
            self.report_metadata = report_metadata
            self.st_metadata = st_metadata
            self.report_frontpage = report_frontpage
            self.st_frontpage = st_frontpage
            self.report_keywords = report_keywords
            self.st_keywords = st_keywords

        def to_dict(self):
            return {'report_metadata': self.report_metadata, 'st_metadata': self.st_metadata,
                    'report_frontpage': self.report_frontpage,
                    'st_frontpage': self.st_frontpage, 'report_keywords': self.report_keywords,
                    'st_keywords': self.st_keywords}

        @classmethod
        def from_dict(cls, dct: Dict[str, bool]):
            return cls(*tuple(dct.values()))

    pandas_serialization_vars = ['dgst', 'name', 'manufacturer', 'scheme', 'security_level', 'not_valid_before',
                                 'not_valid_after', 'report_link', 'st_link', 'src', 'manufacturer_web']

    def __init__(self, status: str, category: str, name: str, manufacturer: str, scheme: str,
                 security_level: Union[str, set], not_valid_before: date,
                 not_valid_after: date, report_link: str, st_link: str, src: str, cert_link: Optional[str],
                 manufacturer_web: Optional[str],
                 protection_profiles: set,
                 maintainance_updates: set,
                 state: Optional[InternalState],
                 pdf_data: Optional[PdfData],
                 cpe_matching: Optional[List[Tuple[str]]]):
        super().__init__()

        self.status = status
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

        if state is None:
            state = self.InternalState()
        self.state = state

        if pdf_data is None:
            pdf_data = self.PdfData()
        self.pdf_data = pdf_data

        if cpe_matching is None:
            cpe_matching = []
        self.cpe_matching = cpe_matching

    @property
    def dgst(self) -> str:
        """
        Computes the primary key of the certificate using first 16 bytes of SHA-256 digest
        """
        return helpers.get_first_16_bytes_sha256(self.category + self.name + self.report_link)

    def to_pandas_tuple(self):
        return tuple(getattr(self, i) for i in self.pandas_serialization_vars)

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
    def from_html_row(cls, row: Tag, status: str, category: str) -> 'CommonCriteriaCert':
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

        return cls(status, category, name, manufacturer, scheme, security_level, not_valid_before, not_valid_after,
                   report_link,
                   st_link, 'html', cert_link, manufacturer_web, protection_profiles, maintainances, None, None, None)

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
            error_msg = f'failed to download report from {cert.report_link}, code: {exit_code}'
            logger.error(f'Cert dgst: {cert.dgst} ' + error_msg)
            cert.state.report_link_ok = False
            cert.state.errors.append(error_msg)
        return cert

    @staticmethod
    def download_pdf_target(cert: 'CommonCriteriaCert') -> 'CommonCriteriaCert':
        exit_code = helpers.download_file(cert.st_link, cert.state.st_pdf_path)
        if exit_code != requests.codes.ok:
            error_msg = f'failed to download ST from {cert.report_link}, code: {exit_code}'
            logger.error(f'Cert dgst: {cert.dgst}' + error_msg)
            cert.state.st_link_ok = False
            cert.state.errors.append(error_msg)
        return cert

    def path_is_corrupted(self, local_path):
        return not local_path.exists() or local_path.stat().st_size < constants.MIN_CORRECT_CERT_SIZE

    @staticmethod
    def convert_report_pdf(cert: 'CommonCriteriaCert') -> 'CommonCriteriaCert':
        exit_code = helpers.convert_pdf_file(cert.state.report_pdf_path, cert.state.report_txt_path, ['-raw'])
        if exit_code != constants.RETURNCODE_OK:
            error_msg = 'failed to convert report pdf->txt'
            logger.error(f'Cert dgst: {cert.dgst}' + error_msg)
            cert.state.report_convert_ok = False
            cert.state.errors.append(error_msg)
        return cert

    @staticmethod
    def convert_target_pdf(cert: 'CommonCriteriaCert') -> 'CommonCriteriaCert':
        exit_code = helpers.convert_pdf_file(cert.state.st_pdf_path, cert.state.st_txt_path, ['-raw'])
        if exit_code != constants.RETURNCODE_OK:
            error_msg = 'failed to convert security target pdf->txt'
            logger.error(f'Cert dgst: {cert.dgst}' + error_msg)
            cert.state.st_convert_ok = False
            cert.state.errors.append(error_msg)
        return cert

    @staticmethod
    def extract_st_pdf_metadata(cert: 'CommonCriteriaCert') -> 'CommonCriteriaCert':
        response, cert.pdf_data.st_metadata = helpers.extract_pdf_metadata(cert.state.st_pdf_path)
        if response != constants.RETURNCODE_OK:
            cert.state.st_extract_ok = False
            cert.state.errors.append(response)
        return cert

    @staticmethod
    def extract_report_pdf_metadata(cert: 'CommonCriteriaCert') -> 'CommonCriteriaCert':
        response, cert.pdf_data.report_metadata = helpers.extract_pdf_metadata(cert.state.report_pdf_path)
        if response != constants.RETURNCODE_OK:
            cert.state.report_extract_ok = False
            cert.state.errors.append(response)
        return cert

    @staticmethod
    def extract_st_pdf_frontpage(cert: 'CommonCriteriaCert') -> 'CommonCriteriaCert':
        cert.pdf_data.st_frontpage = dict()

        response_anssi, cert.pdf_data.st_frontpage['anssi'] = helpers.search_only_headers_anssi(cert.state.st_txt_path)
        response_bsi, cert.pdf_data.st_frontpage['bsi'] = helpers.search_only_headers_bsi(cert.state.st_txt_path)

        if response_anssi != constants.RETURNCODE_OK:
            cert.state.st_extract_ok = False
            cert.state.errors.append(response_anssi)
        if response_bsi != constants.RETURNCODE_OK:
            cert.state.st_extract_ok = False
            cert.state.errors.append(response_bsi)

        return cert

    @staticmethod
    def extract_report_pdf_frontpage(cert: 'CommonCriteriaCert') -> 'CommonCriteriaCert':
        cert.pdf_data.report_frontpage = dict()
        response_bsi, cert.pdf_data.report_frontpage['bsi'] = helpers.search_only_headers_bsi(
            cert.state.report_txt_path)
        response_anssi, cert.pdf_data.report_frontpage['anssi'] = helpers.search_only_headers_anssi(
            cert.state.report_txt_path)

        if response_anssi != constants.RETURNCODE_OK:
            cert.state.report_extract_ok = False
            cert.state.errors.append(response_anssi)
        if response_bsi != constants.RETURNCODE_OK:
            cert.state.report_extract_ok = False
            cert.state.errors.append(response_bsi)

        return cert

    @staticmethod
    def extract_report_pdf_keywords(cert: 'CommonCriteriaCert') -> 'CommonCriteriaCert':
        response, cert.pdf_data.report_keywords = helpers.extract_keywords(cert.state.report_txt_path)
        if response != constants.RETURNCODE_OK:
            cert.state.report_extract_ok = False
        return cert

    @staticmethod
    def extract_st_pdf_keywords(cert: 'CommonCriteriaCert') -> 'CommonCriteriaCert':
        response, cert.pdf_data.st_keywords = helpers.extract_keywords(cert.state.st_txt_path)
        if response != constants.RETURNCODE_OK:
            cert.state.st_extract_ok = False
            cert.state.errors.append(response)
        return cert
