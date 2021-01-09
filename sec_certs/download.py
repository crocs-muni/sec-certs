import os
from multiprocessing.pool import ThreadPool
from pathlib import Path
from tqdm import tqdm
from typing import Sequence, Tuple, List

import requests

from sec_certs.files import search_files

CC_WEB_URL = 'https://www.commoncriteriaportal.org'


def download_file(url: str, output: Path) -> int:
    r = requests.get(url, allow_redirects=True)
    try:
        with open(output, "wb") as f:
            f.write(r.content)
    except (OSError, ConnectionError) as e:
        print('ERROR: Failed to download {} with {}'.format(url, e))
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


def download_cc_web(web_dir: Path, num_threads: int) -> Sequence[Tuple[str, int]]:
    items = [
        ("https://www.commoncriteriaportal.org/products/", web_dir / "cc_products_active.html"),
        ("https://www.commoncriteriaportal.org/products/index.cfm?archived=1",
         web_dir / "cc_products_archived.html"),
        ("https://www.commoncriteriaportal.org/labs/", web_dir / "cc_labs.html"),
        ("https://www.commoncriteriaportal.org/products/certified_products.csv",
         web_dir / "cc_products_active.csv"),
        ("https://www.commoncriteriaportal.org/products/certified_products-archived.csv",
         web_dir / "cc_products_archived.csv"),
        ("https://www.commoncriteriaportal.org/pps/", web_dir / "cc_pp_active.html"),
        ("https://www.commoncriteriaportal.org/pps/collaborativePP.cfm?cpp=1",
         web_dir / "cc_pp_collaborative.html"),
        ("https://www.commoncriteriaportal.org/pps/index.cfm?archived=1",
         web_dir / "cc_pp_archived.html"),
        ("https://www.commoncriteriaportal.org/pps/pps.csv", web_dir / "cc_pp_active.csv"),
        ("https://www.commoncriteriaportal.org/pps/pps-archived.csv",
         web_dir / "cc_pp_archived.csv")]
    return download_parallel(items, num_threads)


def download_cc(walk_dir: Path, cert_list, num_threads: int) -> Sequence[Tuple[str, int]]:
    items = []
    for cert in cert_list:
        if cert[0].find(CC_WEB_URL) != -1:
            items.append((cert[0], walk_dir / "certs" / cert[1]))
        else:
            items.append((CC_WEB_URL + cert[0], walk_dir / "certs" / cert[1]))
        if len(cert) > 2 and cert[3] != "":
            if cert[2].find(CC_WEB_URL) != -1:
                items.append((cert[2], walk_dir / "targets" / cert[3]))
            else:
                items.append((CC_WEB_URL + cert[2], walk_dir / "targets" / cert[3]))
    return download_parallel(items, num_threads)


def download_cc_failed(walk_dir: Path, num_threads: int) -> Sequence[Tuple[str, int]]:
    # obtain list of all downloaded pdf files and their size
    # check for pdf files with too small length
    # generate download script again (single one)

    # visit all relevant subfolders
    sub_folders = ['certs', 'targets']

    # the smallest correct certificate downloaded was 71kB, if server error occurred, it was only 1245 bytes
    MIN_CORRECT_CERT_SIZE = 5000
    download_again = []
    for sub_folder in sub_folders:
        target_dir = walk_dir / sub_folder
        # obtain list of all downloaded pdf files and their size
        files = search_files(target_dir)
        for file_name in files:
            # process only .pdf files
            if not os.path.isfile(file_name):
                continue
            file_ext = file_name[file_name.rfind('.'):].upper()
            if file_ext != '.PDF' and file_ext != '.DOC' and file_ext != '.DOCX':
                continue
            # obtain size of file
            file_size = os.path.getsize(file_name)
            if file_size < MIN_CORRECT_CERT_SIZE:
                # too small file, likely failed download - retry
                file_name_short = file_name[file_name.rfind(os.sep) + 1:]
                download_link = f'{CC_WEB_URL}/files/epfiles/{file_name_short}'
                download_again.append((download_link, file_name))
    return download_parallel(download_again, num_threads)


def download_fips_web(web_dir: Path):
    download_file(
        "https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&CertificateStatus=Active&ValidationYear=0",
        web_dir / "fips_modules_active.html")
    download_file(
        "https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&CertificateStatus=Historical&ValidationYear=0",
        web_dir / "fips_modules_historical.html")
    download_file(
        "https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&CertificateStatus=Revoked&ValidationYear=0",
        web_dir / "fips_modules_revoked.html")


def download_fips(web_dir: Path, policies_dir: Path, num_threads: int, ids: List[str]) \
        -> Tuple[Sequence[Tuple[str, int]], int]:
    web_dir.mkdir(exist_ok=True)
    policies_dir.mkdir(exist_ok=True)

    html_items = [
        (f"https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/{cert_id}",
         web_dir / f"{cert_id}.html") for cert_id in ids if not (web_dir / f'{cert_id}.html').exists()]
    sp_items = [
        (
            f"https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp{cert_id}.pdf",
            policies_dir / f"{cert_id}.pdf") for cert_id in ids if not (policies_dir / f'{cert_id}.pdf').exists()
    ]
    return download_parallel(html_items + sp_items, num_threads), len(html_items) + len(sp_items)
