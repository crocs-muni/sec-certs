import os
from multiprocessing.pool import ThreadPool
from pathlib import Path
from tqdm import tqdm
from typing import Sequence, Tuple

import requests

from .extract_certificates import PDF2TEXT_CONVERT
from .files import search_files, FILE_ERRORS_STRATEGY

CC_WEB_URL = 'https://www.commoncriteriaportal.org'


def download_file(url: str, output: Path) -> int:
    r = requests.get(url, allow_redirects=True)
    with output.open("wb") as f:
        f.write(r.content)
    return r.status_code


def download_parallel(items: Sequence[Tuple[str, Path]], num_threads: int) -> Sequence[int]:
    responses = []
    with tqdm(total=len(items)) as progress:
        for response in ThreadPool(num_threads).imap(download_file, items):
            progress.update(1)
            responses.append(response)
    return responses


def generate_download_script(file_name, certs_dir, targets_dir, base_url, download_files_certs):
    with open(file_name, "w", errors=FILE_ERRORS_STRATEGY) as write_file:
        # certs files
        if certs_dir != '':
            write_file.write(f'mkdir \"{certs_dir}\"\n')
            write_file.write(f'cd \"{certs_dir}\"\n\n')
        for cert in download_files_certs:
            # double %% is necessary to prevent replacement of %2 within script (second argument of script)
            file_name_short_web = cert[0].replace(' ', '%%20')

            if file_name_short_web.find(base_url) != -1:
                # base url already included
                write_file.write(
                    f'curl \"{file_name_short_web}\" -o \"{cert[1]}\"\n')
            else:
                # insert base url
                write_file.write(
                    f'curl \"{base_url}{file_name_short_web}\" -o \"{cert[1]}\"\n')
            write_file.write(f'{PDF2TEXT_CONVERT} \"{cert[1]}\"\n\n')

        if len(download_files_certs) > 0 and len(cert) > 2:
            # security targets file
            if targets_dir != '':
                write_file.write('\n\ncd ..\n')
                write_file.write(f'mkdir \"{targets_dir}\"\n')
                write_file.write(f'cd \"{targets_dir}\"\n\n')
            for cert in download_files_certs:
                # double %% is necessary to prevent replacement of %2 within script (second argument of script)
                file_name_short_web = cert[2].replace(' ', '%%20')
                if file_name_short_web.find(base_url) != -1:
                    # base url already included
                    write_file.write(
                        f'curl \"{file_name_short_web}\" -o \"{cert[3]}\"\n')
                else:
                    # insert base url
                    write_file.write(
                        f'curl \"{base_url}{file_name_short_web}\" -o \"{cert[3]}\"\n')
                write_file.write(f'{PDF2TEXT_CONVERT} \"{cert[3]}\"\n\n')


def download_cc_web(web_dir: Path, num_threads: int) -> Sequence[int]:
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


def download_cc(walk_dir: Path, cert_list, num_threads: int) -> Sequence[int]:
    items = []
    for cert in cert_list:
        if cert[0].find(CC_WEB_URL) != -1:
            items.append((cert[0], walk_dir / "certs" / cert[1]))
        else:
            items.append((CC_WEB_URL + cert[0], walk_dir / "certs" / cert[1]))
        if len(cert) > 2:
            if cert[2].find(CC_WEB_URL) != -1:
                items.append((cert[2], walk_dir / "targets" / cert[3]))
            else:
                items.append((CC_WEB_URL + cert[2], walk_dir / "targets" / cert[3]))
    return download_parallel(items, num_threads)


def generate_failed_download_script(base_dir: Path):
    # obtain list of all downloaded pdf files and their size
    # check for pdf files with too small length
    # generate download script again (single one)

    # visit all relevant subfolders
    sub_folders = ['active/certs', 'active/targets', 'active_update/certs', 'active_update/targets',
                   'archived/certs', 'archived/targets', 'archived_update/certs', 'archived_update/targets']

    # the smallest correct certificate downloaded was 71kB, if server error occurred, it was only 1245 bytes
    MIN_CORRECT_CERT_SIZE = 5000
    download_again = []
    for sub_folder in sub_folders:
        target_dir = base_dir / sub_folder
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
                # double %% is necessary to prevent replacement of %2 within script (second argument of script)
                file_name_short_web = file_name_short.replace(' ', '%%20')
                download_link = f'/files/epfiles/{file_name_short_web}'
                download_again.append((download_link, file_name))

    generate_download_script('download_failed_certs.bat',
                             '', '', CC_WEB_URL, download_again)
    print(
        f'*** Number of files to be re-downloaded again (inside \'{"download_failed_certs.bat"}\'): {len(download_again)}')


def download_fips_web(web_dir: Path):
    download_file("https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search/all",
                  web_dir / "fips_modules_validated.html")


def download_fips(web_dir: Path, policies_dir: Path, num_threads: int) -> Sequence[int]:
    html_items = [
        (f"https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/{cert_id}",
         web_dir / f"{cert_id}.html") for cert_id in range(1, 4001)]
    sp_items = [
        (f"https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp{cert_id}.pdf",
         policies_dir / f"{cert_id}.pdf") for cert_id in range(1, 4001)]
    return download_parallel(html_items + sp_items, num_threads)
