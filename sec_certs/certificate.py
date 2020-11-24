import re
from datetime import datetime, date
from dataclasses import dataclass
import logging
from pathlib import Path
import os
from typing import Union, Optional, List, Dict, ClassVar
from abc import ABC, abstractmethod

from bs4 import Tag, BeautifulSoup, NavigableString

from sec_certs import helpers, extract_certificates


class Certificate(ABC):
    def __init__(self):
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
        return self.__dict__

    @classmethod
    @abstractmethod
    def from_dict(cls, dct: dict) -> 'Certificate':
        raise NotImplementedError('Mot meant to be implemented')


class FIPSCertificate(Certificate):
    FIPS_BASE_URL: ClassVar[str] = 'https://csrc.nist.gov'
    FIPS_MODULE_URL: ClassVar[
        str] = 'https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/'

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
                 algorithms: Optional[List[str]],
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
                 connections: List):
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

    def __str__(self) -> str:
        return str(self.cert_id)

    @property
    def dgst(self) -> str:
        return self.cert_id

    @classmethod
    def from_dict(cls, dct: dict) -> 'FIPSCertificate':
        args = tuple(dct.values())
        return FIPSCertificate(*args)

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
        d = {'fips_module_name': None, 'fips_standard': None, 'fips_status': None, 'fips_date_sunset': None,
             'fips_date_validation': None, 'fips_level': None, 'fips_caveat': None, 'fips_exceptions': None,
             'fips_type': None, 'fips_embodiment': None, 'fips_tested_conf': None, 'fips_description': None,
             'fips_vendor': None, 'fips_vendor_www': None, 'fips_lab': None, 'fips_lab_nvlap': None,
             'fips_historical_reason': None, 'fips_algorithms': [], 'fips_mentioned_certs': [],
             'fips_tables_done': False, 'fips_security_policy_www': None, 'fips_certificate_www': None,
             'fips_hw_versions': None, 'fips_fw_versions': None}

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
    def parse_algorithms(current_text: str, in_pdf: bool = False) -> List:
        """
        Parses table of FIPS (non) allowed algorithms
        :param current_text: Contents of the table
        :param in_pdf: Specifies whether the table was found in a PDF security policies file
        :return: list of all found algorithm IDs
        """
        set_items = set()
        for m in re.finditer(rf"(?:#{'?' if in_pdf else 'C?'}\s?|Cert\.?[^. ]*?\s?)(?:[Cc]\s)?(?P<id>\d+)",
                             current_text):
            set_items.add(m.group())

        return list(set_items)

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
            found_items.append({'Name': tds[0].text, 'Certificate': parse_algorithms(tds[1].text)})

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
                html_items_found['fips_mentioned_certs'] += FIPSCertificate.parse_caveat(content)

            elif 'FIPS Algorithms' in title:
                html_items_found['fips_algorithms'] += FIPSCertificate.parse_table(
                    current_div.find('div', class_='col-md-9'))

            elif 'Algorithms' in title:
                html_items_found['fips_algorithms'] += [{'Certificate': x} for x in
                                                        FIPSCertificate.parse_algorithms(content)]

            elif 'tested_conf' in pairs[title]:
                html_items_found[pairs[title]] = [x.text for x in
                                                  current_div.find('div', class_='col-md-9').find_all('li')]
            else:
                html_items_found[pairs[title]] = content

    @staticmethod
    def parse_vendor(current_div: Tag, html_items_found: Dict, current_file: Path):
        vendor_string = current_div.find('div', 'panel-body').find('a')

        if not vendor_string:
            vendor_string = list(current_div.find('div', 'panel-body').children)[0].strip()
            html_items_found['fips_vendor_www'] = ''
        else:
            html_items_found['fips_vendor_www'] = vendor_string.get('href')
            vendor_string = vendor_string.text.strip()

        html_items_found['fips_vendor'] = vendor_string
        if html_items_found['fips_vendor'] == '':
            logging.warning(f"WARNING: NO VENDOR FOUND{current_file}")

    @staticmethod
    def parse_lab(current_div: Tag, html_items_found: Dict, current_file: Path):
        html_items_found['fips_lab'] = list(current_div.find('div', 'panel-body').children)[0].strip()
        html_items_found['fips_nvlap_code'] = \
            list(current_div.find('div', 'panel-body').children)[2].strip().split('\n')[1].strip()

        if html_items_found['fips_lab'] == '':
            logging.warning(f"WARNING: NO LAB FOUND{current_file}")

        if html_items_found['fips_nvlap_code'] == '':
            logging.warning(f"WARNING: NO NVLAP CODE FOUND{current_file}")

    @staticmethod
    def parse_related_files(current_div: Tag, html_items_found: Dict):
        links = current_div.find_all('a')
        ## TODO: break out of circular imports hell
        html_items_found['fips_security_policy_www'] = __import__(
            'sec_certs').certificate.FIPSCertificate.FIPS_BASE_URL + links[0].get('href')

        if len(links) == 2:
            html_items_found['fips_certificate_www'] = __import__(
                'sec_certs').certificate.FIPSCertificate.FIPS_BASE_URL + links[1].get('href')

    @classmethod
    def html_from_file(cls, file: Path) -> 'FIPSCertificate':
        pairs = {
            'Module Name': 'fips_module_name',
            'Standard': 'fips_standard',
            'Status': 'fips_status',
            'Sunset Date': 'fips_date_sunset',
            'Validation Dates': 'fips_date_validation',
            'Overall Level': 'fips_level',
            'Caveat': 'fips_caveat',
            'Security Level Exceptions': 'fips_exceptions',
            'Module Type': 'fips_type',
            'Embodiment': 'fips_embodiment',
            'FIPS Algorithms': 'fips_algorithms',
            'Allowed Algorithms': 'fips_algorithms',
            'Other Algorithms': 'fips_algorithms',
            'Tested Configuration(s)': 'fips_tested_conf',
            'Description': 'fips_description',
            'Historical Reason': 'fips_historical_reason',
            'Hardware Versions': 'fips_hw_versions',
            'Firmware Versions': 'fips_fw_versions'
        }
        items_found = FIPSCertificate.initialize_dictionary()
        items_found['cert_fips_id'] = file.stem

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

        return FIPSCertificate(items_found['cert_fips_id'],
                               items_found['fips_module_name'],
                               items_found['fips_standard'],
                               items_found['fips_status'],
                               items_found['fips_date_sunset'],
                               items_found['fips_date_validation'],
                               items_found['fips_level'],
                               items_found['fips_caveat'],
                               items_found['fips_exceptions'],
                               items_found['fips_type'],
                               items_found['fips_embodiment'],
                               items_found['fips_algorithms'],
                               items_found['fips_tested_conf'],
                               items_found['fips_description'],
                               items_found['fips_mentioned_certs'],
                               items_found['fips_vendor'],
                               items_found['fips_vendor_www'],
                               items_found['fips_lab'],
                               items_found['fips_nvlap_code'],
                               items_found['fips_historical_reason'],
                               items_found['fips_security_policy_www'],
                               items_found['fips_certificate_www'],
                               items_found['fips_hw_versions'],
                               items_found['fips_fw_versions'],
                               False,
                               None,
                               [])


class CommonCriteriaCert(Certificate):
    cc_url = 'http://www.commoncriteriaportal.org'

    @dataclass(eq=True, frozen=True)
    class MaintainanceReport:
        """
        Object for holding maintainance reports.
        """
        maintainance_date: date
        maintainance_title: str
        maintainance_report_link: str
        maintainance_st_link: str

        def __post_init__(self):
            super().__setattr__('maintainance_report_link', helpers.sanitize_link(self.maintainance_report_link))
            super().__setattr__('maintainance_st_link', helpers.sanitize_link(self.maintainance_st_link))
            super().__setattr__('maintainance_title', helpers.sanitize_string(self.maintainance_title))
            super().__setattr__('maintainance_date', helpers.sanitize_date(self.maintainance_date))

        def to_dict(self):
            return self.__dict__

        @classmethod
        def from_dict(cls, dct):
            return cls(*tuple(dct.values()))

        def __lt__(self, other):
            return self.maintainance_date < other.maintainance_date

    @dataclass(eq=True, frozen=True)
    class ProtectionProfile:
        """
        Object for holding protection profiles.
        """
        pp_name: str
        pp_link: Optional[str]

        def __post_init__(self):
            super().__setattr__('pp_name', helpers.sanitize_string(self.pp_name))
            super().__setattr__('pp_link', helpers.sanitize_link(self.pp_link))

        def to_dict(self):
            return self.__dict__

        def __lt__(self, other):
            return self.pp_name < other.pp_name

        @classmethod
        def from_dict(cls, dct):
            return cls(*tuple(dct.values()))

    def __init__(self, category: str, name: str, manufacturer: str, scheme: str,
                 security_level: Union[str, set], not_valid_before: date,
                 not_valid_after: date, report_link: str, st_link: str, src: str, cert_link: Optional[str],
                 manufacturer_web: Optional[str],
                 protection_profiles: set,
                 maintainance_updates: set):
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
            logging.warning(
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
            else:
                if getattr(self, att) != getattr(other, att):
                    logging.warning(
                        f'When merging certificates with dgst {self.dgst}, the following mismatch occured: Attribute={att}, self[{att}]={getattr(self, att)}, other[{att}]={getattr(other, att)}')
        if self.src != other.src:
            self.src = self.src + ' + ' + other.src

    def to_dict(self) -> dict:
        return self.__dict__

    @classmethod
    def from_dict(cls, dct: dict) -> 'CommonCriteriaCert':
        dct['maintainance_updates'] = set(dct['maintainance_updates'])
        dct['protection_profiles'] = set(dct['protection_profiles'])
        args = tuple(dct.values())

        return cls(*args)

    @classmethod
    def from_html_row(cls, row: Tag, category: str) -> 'CommonCriteriaCert':
        """
        Creates a CC certificate from html row
        """

        def get_name(cell: Tag) -> str:
            return list(cell.stripped_strings)[0]

        def get_manufacturer(cell: Tag) -> Optional[str]:
            if lst := list(cell.stripped_strings):
                return lst[0]
            else:
                return None

        def get_scheme(cell: Tag) -> str:
            return list(cell.stripped_strings)[0]

        def get_security_level(cell: Tag) -> set:
            return set(cell.stripped_strings)

        def get_manufacturer_web(cell: Tag) -> Optional[str]:
            for link in cell.find_all('a'):
                if link is not None and link.get('title') == 'Vendor\'s web site' and link.get('href') != 'http://':
                    return link.get('href')
            return None

        def get_protection_profiles(cell: Tag) -> set:
            protection_profiles = set()
            for link in list(cell.find_all('a')):
                if link.get('href') is not None and '/ppfiles/' in link.get('href'):
                    protection_profiles.add(CommonCriteriaCert.ProtectionProfile(str(link.contents[0]),
                                                                                 CommonCriteriaCert.cc_url + link.get(
                                                                                     'href')))
            return protection_profiles

        def get_date(cell: Tag) -> date:
            text = cell.get_text()
            extracted_date = datetime.strptime(text, '%Y-%m-%d').date() if text else None
            return extracted_date

        def get_report_st_links(cell: Tag) -> (str, str):
            links = cell.find_all('a')
            # TODO: Exception checks
            assert links[1].get('title').startswith('Certification Report')
            assert links[2].get('title').startswith('Security Target')

            report_link = CommonCriteriaCert.cc_url + links[1].get('href')
            security_target_link = CommonCriteriaCert.cc_url + links[2].get('href')

            return report_link, security_target_link

        def get_cert_link(cell: Tag) -> Optional[str]:
            links = cell.find_all('a')
            return CommonCriteriaCert.cc_url + links[0].get('href') if links else None

        def get_maintainance_div(cell: Tag) -> Optional[Tag]:
            divs = cell.find_all('div')
            for d in divs:
                if d.find('div') and d.stripped_strings and list(d.stripped_strings)[0] == 'Maintenance Report(s)':
                    return d
            return None

        def get_maintainance_updates(main_div: Tag) -> set:
            possible_updates = list(main_div.find_all('li'))
            maintainance_updates = set()
            for u in possible_updates:
                text = list(u.stripped_strings)[0]
                main_date = datetime.strptime(text.split(' ')[0], '%Y-%m-%d').date() if text else None
                main_title = text.split('– ')[1]
                main_report_link = None
                main_st_link = None
                links = u.find_all('a')
                for l in links:
                    if l.get('title').startswith('Maintenance Report:'):
                        main_report_link = CommonCriteriaCert.cc_url + l.get('href')
                    elif l.get('title').startswith('Maintenance ST'):
                        main_st_link = CommonCriteriaCert.cc_url + l.get('href')
                    else:
                        logging.error('Unknown link in Maintenance part!')
                maintainance_updates.add(
                    CommonCriteriaCert.MaintainanceReport(main_date, main_title, main_report_link, main_st_link))
            return maintainance_updates

        cells = list(row.find_all('td'))
        if len(cells) != 7:
            logging.error('Unexpected number of cells in CC html row.')
            raise

        name = get_name(cells[0])
        manufacturer = get_manufacturer(cells[1])
        manufacturer_web = get_manufacturer_web(cells[1])
        scheme = get_scheme(cells[6])
        security_level = get_security_level(cells[5])
        protection_profiles = get_protection_profiles(cells[0])
        not_valid_before = get_date(cells[3])
        not_valid_after = get_date(cells[4])
        report_link, st_link = get_report_st_links(cells[0])
        cert_link = get_cert_link(cells[2])

        maintainance_div = get_maintainance_div(cells[0])
        maintainances = get_maintainance_updates(maintainance_div) if maintainance_div else set()

        return cls(category, name, manufacturer, scheme, security_level, not_valid_before, not_valid_after, report_link,
                   st_link, 'html', cert_link, manufacturer_web, protection_profiles, maintainances)
