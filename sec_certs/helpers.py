import re
from typing import Sequence, Tuple, Optional, Set, List, Dict

import pikepdf
import requests
from multiprocessing.pool import ThreadPool
from pathlib import Path
from tqdm import tqdm
import hashlib
import html
from typing import Union
from datetime import date
import numpy as np
import pandas as pd
from bs4 import Tag, NavigableString



def download_file(url: str, output: Path) -> int:
    r = requests.get(url, allow_redirects=True)
    with output.open('wb') as f:
        f.write(r.content)
    return r.status_code


def download_parallel(items: Sequence[Tuple[str, Path]], num_threads: int) -> Sequence[Tuple[str, int]]:
    def download(url_output):
        url, output = url_output
        return url, download_file(url, output)

    pool = ThreadPool(num_threads)
    responses = []
    with tqdm(total=len(items)) as progress:
        for response in pool.imap(download, items):
            progress.update(1)
            responses.append(response)
    pool.close()
    pool.join()
    return responses


def get_first_16_bytes_sha256(string: str) -> str:
    return hashlib.sha256(string.encode('utf-8')).hexdigest()[:16]


def sanitize_link(record: str) -> Union[str, None]:
    if not record:
        return None
    return record.replace(':443', '').replace(' ', '%20')


def sanitize_date(record: Union[pd.Timestamp, date, np.datetime64]) -> Union[date, None]:
    if pd.isnull(record):
        return None
    elif isinstance(record, pd.Timestamp):
        return record.date()
    else:
        return record


def sanitize_string(record: str) -> Union[str, None]:
    if not record:
        return None
    else:
        # TODO: There is a certificate with name 'ATMEL Secure Microcontroller AT90SC12872RCFT &#x2f; AT90SC12836RCFT rev. I &amp;&#x23;38&#x3b; J' that has to be unescaped twice
        string = html.unescape(html.unescape(record)).replace('\n', '')
        return ' '.join(string.split())


def sanitize_security_levels(record: Union[str, set]) -> set:
    if isinstance(record, str):
        record = set(record.split(','))

    if 'PP\xa0Compliant' in record:
        record.remove('PP\xa0Compliant')

    if 'None' in record:
        record.remove('None')

    return record


def sanitize_protection_profiles(record: str) -> list:
    if not record:
        return []
    return record.split(',')


# TODO: realize whether this stays or goes somewhere else
def parse_list_of_tables(txt: str) -> Set[str]:
    """
    Parses list of tables from function find_tables(), finds ones that mention algorithms
    :param txt: chunk of text
    :return: set of all pages mentioning algorithm table
    """
    rr = re.compile(r"^.+?(?:[Ff]unction|[Aa]lgorithm).+?(?P<page_num>\d+)$", re.MULTILINE)
    pages = set()
    for m in rr.finditer(txt):
        pages.add(m.group('page_num'))
    return pages


def find_tables_iterative(file_text: str) -> List[int]:
    current_page = 1
    pages = set()
    for line in file_text.split('\n'):
        if '\f' in line:
            current_page += 1
        if line.startswith('Table ') or line.startswith('Exhibit'):
            pages.add(current_page)
    if not pages:
        print('~' * 20, 'No pages found', '~' * 20)
    return list(pages)


def find_tables(txt: str, file_name: Path) -> Optional[List]:
    """
    Function that tries to pages in security policy pdf files, where it's possible to find a table containing
    algorithms
    :param txt: file in .txt format (output of pdftotext)
    :param file_name: name of the file
    :return:    list of pages possibly containing a table
                None if these cannot be found
    """
    # Look for "List of Tables", where we can find exactly tables with page num
    tables_regex = re.compile(r"^(?:(?:[Tt]able\s|[Ll]ist\s)(?:[Oo]f\s))[Tt]ables[\s\S]+?\f", re.MULTILINE)
    table = tables_regex.search(txt)
    if table:
        rb = parse_list_of_tables(table.group())
        if rb:
            return list(rb)
        return None

    # Otherwise look for "Table" in text and \f representing footer, then extract page number from footer
    print("~" * 20, file_name, '~' * 20)
    rb = find_tables_iterative(txt)
    return rb if rb else None


def repair_pdf(file: Path):
    """
    Some pdfs can't be opened by PyPDF2 - opening them with pikepdf and then saving them fixes this issue.
    By opening this file in a pdf reader, we can already extract number of pages
    :param file: file name
    :return: number of pages in pdf file
    """
    pdf = pikepdf.Pdf.open(file, allow_overwriting_input=True)
    pdf.save(file)


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


def parse_html_main(current_div: Tag, html_items_found: Dict, pairs: Dict):
    title = current_div.find('div', class_='col-md-3').text.strip()
    content = current_div.find('div', class_='col-md-9').text.strip() \
        .replace('\n', '').replace('\t', '').replace('    ', ' ')

    if title in pairs:
        if 'date' in pairs[title]:
            html_items_found[pairs[title]] = content.split(';')
        elif 'caveat' in pairs[title]:
            html_items_found[pairs[title]] = content
            html_items_found['fips_mentioned_certs'] += parse_caveat(content)

        elif 'FIPS Algorithms' in title:
            html_items_found['fips_algorithms'] += parse_table(current_div.find('div', class_='col-md-9'))

        elif 'Algorithms' in title:
            html_items_found['fips_algorithms'] += [{'Certificate': x} for x in parse_algorithms(content)]

        elif 'tested_conf' in pairs[title]:
            html_items_found[pairs[title]] = [x.text for x in
                                              current_div.find('div', class_='col-md-9').find_all('li')]
        else:
            html_items_found[pairs[title]] = content


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
        print("WARNING: NO VENDOR FOUND", current_file)


def parse_lab(current_div: Tag, html_items_found: Dict, current_file: Path):
    html_items_found['fips_lab'] = list(current_div.find('div', 'panel-body').children)[0].strip()
    html_items_found['fips_nvlap_code'] = \
        list(current_div.find('div', 'panel-body').children)[2].strip().split('\n')[1].strip()

    if html_items_found['fips_lab'] == '':
        print("WARNING: NO LAB FOUND", current_file)

    if html_items_found['fips_nvlap_code'] == '':
        print("WARNING: NO NVLAP CODE FOUND", current_file)


def parse_related_files(current_div: Tag, html_items_found: Dict):
    links = current_div.find_all('a')
    html_items_found['fips_security_policy_www'] = __import__('.certificate').FIPSCertificate.fips_base_url + links[0].get('href')

    if len(links) == 2:
        html_items_found['fips_certificate_www'] = __import__('.certificate').FIPSCertificate.fips_base_url + links[1].get('href')


def initialize_dictionary() -> Dict:
    d = {'fips_module_name': None, 'fips_standard': None, 'fips_status': None, 'fips_date_sunset': None,
         'fips_date_validation': None, 'fips_level': None, 'fips_caveat': None, 'fips_exceptions': None,
         'fips_type': None, 'fips_embodiment': None, 'fips_tested_conf': None, 'fips_description': None,
         'fips_vendor': None, 'fips_vendor_www': None, 'fips_lab': None, 'fips_lab_nvlap': None,
         'fips_historical_reason': None, 'fips_algorithms': [], 'fips_mentioned_certs': [],
         'fips_tables_done': False, 'fips_security_policy_www': None, 'fips_certificate_www': None,
         'fips_hw_versions': None, 'fips_fw_versions': None}

    return d
