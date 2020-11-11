from typing import Sequence, Tuple
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
        return html.unescape(html.unescape(record)).replace('\r\n', ' ').replace('\n', '')


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