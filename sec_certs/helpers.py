import re
from typing import Sequence, Tuple, Optional, Set, List, Dict
import logging
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
import subprocess
from bs4 import Tag, NavigableString

import sec_certs.constants as constants


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


def get_sha256_filepath(filepath):
    hash_sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()


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
        logging.warning('No pages found')
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
    logging.info(f'parsing tables in {file_name}')
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


def convert_pdf_file(filepaths: Tuple[Path, Path], options):
    pdf_path, txt_path = filepaths[0], filepaths[1]
    proc_result = subprocess.run(['pdftotext', *options, pdf_path, txt_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if proc_result.returncode != constants.RETURNCODE_OK:
        logging.error(f'Converting pdf {pdf_path} resulted into the following result: {proc_result}')
    return proc_result




