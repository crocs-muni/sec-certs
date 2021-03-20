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
import sec_certs.constants as constants
from enum import Enum
from rapidfuzz import process, fuzz
import matplotlib.pyplot as plt

from PyPDF2 import PdfFileReader

import sec_certs.extract_certificates as extract_certificates
from sec_certs.cert_rules import REGEXEC_SEP
from sec_certs.cert_rules import rules as cc_search_rules

logger = logging.getLogger(__name__)


def download_file(url: str, output: Path) -> int:
    try:
        r = requests.get(url, allow_redirects=True, timeout=constants.REQUEST_TIMEOUT)
        if r.status_code == requests.codes.ok:
            with output.open("wb") as f:
                f.write(r.content)
        return r.status_code
    except requests.exceptions.Timeout:
        return requests.codes.timeout
    except Exception as e:
        logger.error(f'Failed to download from {url}; {e}')
        return constants.RETURNCODE_NOK


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
    rr = re.compile(r"^.+?(?:[Ff]unction|[Aa]lgorithm|[Ss]ecurity [Ff]unctions?).+?(?P<page_num>\d+)$", re.MULTILINE)
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
        logger.warning('No pages found')
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
    logger.info(f'parsing tables in {file_name}')
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


def convert_pdf_file(pdf_path: Path, txt_path: Path, options):
    response = subprocess.run(['pdftotext', *options, pdf_path, txt_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60).returncode
    if response == 0:
        return constants.RETURNCODE_OK
    else:
        return constants.RETURNCODE_NOK


def extract_pdf_metadata(filepath: Path):
    metadata = dict()

    try:
        metadata['pdf_file_size_bytes'] = filepath.stat().st_size
        with filepath.open('rb') as handle:
            pdf = PdfFileReader(handle)

            metadata['pdf_is_encrypted'] = pdf.getIsEncrypted()
            metadata['pdf_number_of_pages'] = pdf.getNumPages()

            for key, val in pdf.getDocumentInfo().items():
                metadata[key] = str(val)

    except Exception as e:
        error_msg = f'Failed to read metadata of {filepath}, error: {e}'
        logger.error(error_msg)
        return error_msg, None

    return constants.RETURNCODE_OK, metadata


# TODO: Please, refactor me. I reallyyyyyyyyyyyyy need it!!!!!!
def search_only_headers_anssi(filepath: Path):
    class HEADER_TYPE(Enum):
        HEADER_FULL = 1
        HEADER_MISSING_CERT_ITEM_VERSION = 2
        HEADER_MISSING_PROTECTION_PROFILES = 3
        HEADER_DUPLICITIES = 4

    rules_certificate_preface = [
        (HEADER_TYPE.HEADER_FULL,
         'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.*)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.*)Conformité à un profil de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeurs(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'Référence du rapport de certification(.+)Nom du produit(.+)()Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeur (.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'Référence du rapport de certification(.+)Nom des produits(.+)Référence/version des produits(.+)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeur\(s\)(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'Référence du rapport de certification(.+)Nom des produits(.+)Référence/version des produits(.+)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeur (.+)Centre d\'évaluation(.+)Accords de reconnaissance'),
        (HEADER_TYPE.HEADER_FULL,
         'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité aux profils de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeur\(s\)(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité à un profil de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeur\(s\)(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité à un profil de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeur (.+)Centre d’évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité à des profils de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeurs(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité aux profils de protection(.+)Critères d\’évaluation et version(.+)Niveau d\’évaluation(.+)Développeurs(.+)Centre d\’évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'Référence du rapport de certification(.+)Nom du produit \(référence/version\)(.+)Nom de la TOE \(référence/version\)(.+)Conformité à un profil de protection(.+)Critères d\’évaluation et version(.+)Niveau d\’évaluation(.+)Développeurs(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité aux profil de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeur\(s\)(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeur\(s\)(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'Référence du rapport de certification(.+)Nom du produit \(référence/version\)(.+)Nom de la TOE \(référence/version\)(.+)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'Référence du rapport de certification(.+)Nom du produit(.+)Référence du produit(.+)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité aux profils de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),

        (HEADER_TYPE.HEADER_FULL,
         'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeurs(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur\(s\)(.+)dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur (.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© Ã  des profils de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeurs(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit \(rÃ©fÃ©rence/version\)(.+)Nom de la TOE \(rÃ©fÃ©rence/version\)(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeurs(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'Certification Report(.+)Nom du produit(.+)Référence/version du produit(.*)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© aux profisl de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeurs(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur (.+)Centres dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)Version du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur (.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© aux profils de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur\(s\)(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)Versions du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur (.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeurs(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL,
         'Certification report reference(.+)Product name(.+)Product reference(.+)Protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developer (.+)Evaluation facility(.+)Recognition arrangements'),
        (HEADER_TYPE.HEADER_FULL,
         'Certification report reference(.+)Product name(.+)Product reference(.+)Protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developer (.+)Evaluation facility(.+)Mutual Recognition Agreements'),
        (HEADER_TYPE.HEADER_FULL,
         'Certification report reference(.+)Product name(.+)Product reference(.+)Protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developers(.+)Evaluation facility(.+)Recognition arrangements'),
        (HEADER_TYPE.HEADER_FULL,
         'Certification report reference(.+)Product name(.+)Product reference(.+)Protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developer\(s\)(.+)Evaluation facility(.+)Recognition arrangements'),
        (HEADER_TYPE.HEADER_FULL,
         'Certification report reference(.+)Products names(.+)Products references(.+)protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developers(.+)Evaluation facility(.+)Recognition arrangements'),
        (HEADER_TYPE.HEADER_FULL,
         'Certification report reference(.+)Product name \(reference / version\)(.+)TOE name \(reference / version\)(.+)Protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developers(.+)Evaluation facility(.+)Recognition arrangements'),
        (HEADER_TYPE.HEADER_FULL,
         'Certification report reference(.+)TOE name(.+)Product\'s reference/ version(.+)TOE\'s reference/ version(.+)Conformité à un profil de protection(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developer (.+)Evaluation facility(.+)Recognition arrangements'),

        # corrupted text (duplicities)
        (HEADER_TYPE.HEADER_DUPLICITIES,
         'RÃ©fÃ©rencce du rapport de d certification n(.+)Nom du p produit(.+)RÃ©fÃ©rencce/version du produit(.+)ConformiitÃ© Ã  un profil de d protection(.+)CritÃ¨res d dâ€™Ã©valuation ett version(.+)Niveau dâ€™â€™Ã©valuation(.+)DÃ©velopp peurs(.+)Centre dâ€™â€™Ã©valuation(.+)Accords d de reconnaisssance applicab bles'),

        # rules without product version
        (HEADER_TYPE.HEADER_MISSING_CERT_ITEM_VERSION,
         'Référence du rapport de certification(.+)Nom et version du produit(.+)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_MISSING_CERT_ITEM_VERSION,
         'Référence du rapport de certification(.+)Nom et version du produit(.+)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeur (.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_MISSING_CERT_ITEM_VERSION,
         'Référence du rapport de certification(.+)Nom du produit(.+)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),

        # rules without protection profile
        (HEADER_TYPE.HEADER_MISSING_PROTECTION_PROFILES,
         'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),
    ]


    # statistics about rules success rate
    num_rules_hits = {}
    for rule in rules_certificate_preface:
        num_rules_hits[rule[1]] = 0

    items_found = {}

    try:
        whole_text, whole_text_with_newlines, was_unicode_decode_error = extract_certificates.load_cert_file(filepath)

        # for ANSII and DCSSI certificates, front page starts only on third page after 2 newpage signs
        pos = whole_text.find('')
        if pos != -1:
            pos = whole_text.find('', pos)
            if pos != -1:
                whole_text = whole_text[pos:]

        no_match_yet = True
        other_rule_already_match = False
        rule_index = -1
        for rule in rules_certificate_preface:
            rule_index += 1
            rule_and_sep = rule[1] + REGEXEC_SEP

            for m in re.finditer(rule_and_sep, whole_text):
                if no_match_yet:
                    items_found[constants.TAG_HEADER_MATCH_RULES] = []
                    no_match_yet = False

                # insert rule if at least one match for it was found
                if rule not in items_found[constants.TAG_HEADER_MATCH_RULES]:
                    items_found[constants.TAG_HEADER_MATCH_RULES].append(rule[1])

                if not other_rule_already_match:
                    other_rule_already_match = True
                else:
                    logger.warning(f'WARNING: multiple rules are matching same certification document: {filepath}')

                num_rules_hits[rule[1]] += 1  # add hit to this rule
                match_groups = m.groups()
                index_next_item = 0
                items_found[constants.TAG_CERT_ID] = extract_certificates.normalize_match_string(match_groups[index_next_item])
                index_next_item += 1

                items_found[constants.TAG_CERT_ITEM] = extract_certificates.normalize_match_string(match_groups[index_next_item])
                index_next_item += 1

                if rule[0] == HEADER_TYPE.HEADER_MISSING_CERT_ITEM_VERSION:
                    items_found[constants.TAG_CERT_ITEM_VERSION] = ''
                else:
                    items_found[constants.TAG_CERT_ITEM_VERSION] = extract_certificates.normalize_match_string(match_groups[index_next_item])
                    index_next_item += 1

                if rule[0] == HEADER_TYPE.HEADER_MISSING_PROTECTION_PROFILES:
                    items_found[constants.TAG_REFERENCED_PROTECTION_PROFILES] = ''
                else:
                    items_found[constants.TAG_REFERENCED_PROTECTION_PROFILES] = extract_certificates.normalize_match_string(match_groups[index_next_item])
                    index_next_item += 1

                items_found[constants.TAG_CC_VERSION] = extract_certificates.normalize_match_string(match_groups[index_next_item])
                index_next_item += 1

                items_found[constants.TAG_CC_SECURITY_LEVEL] = extract_certificates.normalize_match_string(match_groups[index_next_item])
                index_next_item += 1

                items_found[constants.TAG_DEVELOPER] = extract_certificates.normalize_match_string(match_groups[index_next_item])
                index_next_item += 1

                items_found[constants.TAG_CERT_LAB] = extract_certificates.normalize_match_string(match_groups[index_next_item])
                index_next_item += 1
    except Exception as e:
        error_msg = f'Failed to parse ANSSI frontpage headers from {filepath}; {e}'
        logger.error(error_msg)
        return error_msg, None

    # if True:
    #     print('# hits for rule')
    #     sorted_rules = sorted(num_rules_hits.items(),
    #                           key=operator.itemgetter(1), reverse=True)
    #     used_rules = []
    #     for rule in sorted_rules:
    #         print('{:4d} : {}'.format(rule[1], rule[0]))
    #         if rule[1] > 0:
    #             used_rules.append(rule[0])

    return constants.RETURNCODE_OK, items_found

# TODO: Please refactor me. I need it so badlyyyyyy!!!
def search_only_headers_bsi(filepath: Path):
    LINE_SEPARATOR_STRICT = ' '
    NUM_LINES_TO_INVESTIGATE = 15
    rules_certificate_preface = [
        '(BSI-DSZ-CC-.+?) (?:for|For) (.+?) from (.*)',
        '(BSI-DSZ-CC-.+?) zu (.+?) der (.*)',
    ]

    items_found = {}
    no_match_yet = True

    try:
        # Process front page with info: cert_id, certified_item and developer
        whole_text, whole_text_with_newlines, was_unicode_decode_error = extract_certificates.load_cert_file(filepath, NUM_LINES_TO_INVESTIGATE, LINE_SEPARATOR_STRICT)

        for rule in rules_certificate_preface:
            rule_and_sep = rule + REGEXEC_SEP

            for m in re.finditer(rule_and_sep, whole_text):
                if no_match_yet:
                    items_found[constants.TAG_HEADER_MATCH_RULES] = []
                    no_match_yet = False

                # insert rule if at least one match for it was found
                if rule not in items_found[constants.TAG_HEADER_MATCH_RULES]:
                    items_found[constants.TAG_HEADER_MATCH_RULES].append(rule)

                match_groups = m.groups()
                cert_id = match_groups[0]
                certified_item = match_groups[1]
                developer = match_groups[2]

                FROM_KEYWORD_LIST = [' from ', ' der ']
                for from_keyword in FROM_KEYWORD_LIST:
                    from_keyword_len = len(from_keyword)
                    if certified_item.find(from_keyword) != -1:
                        logger.warning(f'string {from_keyword} detected in certified item - shall not be here, fixing...')
                        certified_item_first = certified_item[:certified_item.find(from_keyword)]
                        developer = certified_item[certified_item.find(from_keyword) + from_keyword_len:]
                        certified_item = certified_item_first
                        continue

                end_pos = developer.find('\f-')
                if end_pos == -1:
                    end_pos = developer.find('\fBSI')
                if end_pos == -1:
                    end_pos = developer.find('Bundesamt')
                if end_pos != -1:
                    developer = developer[:end_pos]

                items_found[constants.TAG_CERT_ID] = extract_certificates.normalize_match_string(cert_id)
                items_found[constants.TAG_CERT_ITEM] = extract_certificates.normalize_match_string(certified_item)
                items_found[constants.TAG_DEVELOPER] = extract_certificates.normalize_match_string(developer)
                items_found[constants.TAG_CERT_LAB] = 'BSI'

        # Process page with more detailed certificate info
        # PP Conformance, Functionality, Assurance
        rules_certificate_third = ['PP Conformance: (.+)Functionality: (.+)Assurance: (.+)The IT Product identified']

        whole_text, whole_text_with_newlines, was_unicode_decode_error = extract_certificates.load_cert_file(filepath)

        for rule in rules_certificate_third:
            rule_and_sep = rule + REGEXEC_SEP

            for m in re.finditer(rule_and_sep, whole_text):
                # check if previous rules had at least one match
                if not constants.TAG_CERT_ID in items_found.keys():
                    logger.error('ERROR: front page not found for file: {}'.format(filepath))

                match_groups = m.groups()
                ref_protection_profiles = match_groups[0]
                cc_version = match_groups[1]
                cc_security_level = match_groups[2]

                items_found[constants.TAG_REFERENCED_PROTECTION_PROFILES] = extract_certificates.normalize_match_string(ref_protection_profiles)
                items_found[constants.TAG_CC_VERSION] = extract_certificates.normalize_match_string(cc_version)
                items_found[constants.TAG_CC_SECURITY_LEVEL] = extract_certificates.normalize_match_string(cc_security_level)

        # print('\n*** Certificates without detected preface:')
        # for file_name in files_without_match:
        #     print('No hits for {}'.format(file_name))
        # print('Total no hits files: {}'.format(len(files_without_match)))
        # print('\n**********************************')
    except Exception as e:
        error_msg = f'Failed to parse BSI headers from frontpage: {filepath}; {e}'
        logger.error(error_msg)
        return error_msg, None

    return constants.RETURNCODE_OK, items_found

def extract_keywords(filepath: Path) -> Tuple[int, Optional[Dict[str, str]]]:
    try:
        result = extract_certificates.parse_cert_file(filepath, cc_search_rules, -1, extract_certificates.LINE_SEPARATOR)[0]
    except Exception as e:
        error_msg = f'Failed to parse keywords from: {filepath}; {e}'
        logger.error(error_msg)
        return error_msg, None
    return constants.RETURNCODE_OK, result


def match_certs(certs: Dict[str, str], cpes: List[str]):
    results = {}
    for dgst, cert_name in certs.items():
        results[dgst] = process.extract(cert_name, cpes, scorer=fuzz.token_set_ratio, limit=10)
    return results

def analyze_matched_algs(data: Dict):
    pd_data = pd.Series(data)
    pd_data.hist(bins=50)
    plt.show()

    sorted_data = pd_data.value_counts(ascending=True)

    logging.info(sorted_data.where(sorted_data > 1).dropna())