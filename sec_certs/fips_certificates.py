#!/usr/bin/env python3
import json
import os
import re
import time
from pathlib import Path
from typing import Set, Optional, List
from bs4 import BeautifulSoup

from graphviz import Digraph
import click
import pikepdf
# from camelot import read_pdf
from tabula import read_pdf

from .download import download_fips_web, download_fips
from . import extract_certificates
from .files import load_json_files, FILE_ERRORS_STRATEGY, search_files
from .cert_rules import rules_fips_htmls as RE_FIPS_HTMLS

FIPS_BASE_URL = 'https://csrc.nist.gov'
FIPS_MODULE_URL = 'https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/'


def extract_filename(file: str) -> str:
    """
    Extracts filename from path
    @param file: UN*X path
    :return: filename without last extension
    """
    return os.path.splitext(os.path.basename(file))[0]


def parse_ul(text):
    """
    Parses content between <ul> tags in FIPS .html CMVP page
    :param text: text in <ul> tags
    :return: all <li> elements
    """
    p = re.compile(r"<li>(.*?)<\/li>")
    return p.findall(text)


def parse_table(text):
    """
    Parses content of <table> tags in FIPS .html CMVP page
    :param text: text in <table> tags
    :return: list of all found algorithm IDs
    """
    found_items = []
    lines = iter([line for line in text.split('\n') if line])
    if len(text.split('\n')) > 1:
        for line in lines:
            found_items.append({'Name': line, 'Certificate': parse_algorithms(next(lines))})

    return found_items


def parse_algorithms(text, in_pdf=False):
    """
    Parses table of FIPS (non) allowed algorithms
    :param text: Contents of the table
    :param in_pdf: Specifies whether the table was found in a PDF security policies file
    :return: list of all found algorithm IDs
    """
    set_items = set()
    for m in re.finditer(rf"(?:#{'?' if in_pdf else 'C?'}\s?|Cert\.?[^. ]*?\s?)(?:[Cc]\s)?(?P<id>\d+)", text):
        set_items.add(m.group())

    return list(set_items)


def parse_caveat(text):
    """
    Parses content of "Caveat" of FIPS CMVP .html file
    :param text: text of "Caveat"
    :return: list of all found algorithm IDs
    """
    items_found = []
    r_key = r"(?:#\s?|Cert\.?(?!.\s)\s?|Certificate\s?)(?P<id>\d+)"
    for m in re.finditer(r_key, text):
        if r_key in items_found and m.group() in items_found[0]:
            items_found[0][m.group()]['count'] += 1
        else:
            items_found.append({r"(?:#\s?|Cert\.?(?!.\s)\s?|Certificate\s?)(?P<id>\d+?})": {m.group(): {'count': 1}}})

    return items_found


def initialize_entry(input_dictionary):
    """
    Initialize input dictionary with elements that shuold be always processed
    :param input_dictionary: dictionary used as "all_items"
    """
    input_dictionary['fips_exceptions'] = []
    input_dictionary['fips_tested_conf'] = []
    input_dictionary['fips_mentioned_certs'] = []

    input_dictionary['fips_algorithms'] = []
    input_dictionary['fips_caveat'] = []
    input_dictionary['tables_done'] = False
    input_dictionary['fips_module_name'] = 'Undefined'


def fips_search_html(base_dir, output_file, dump_to_file=False):
    all_found_items = {}
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
        'Tested Configuration(s)': 'fips_tested_conf',
        'Description': 'fips_description'
    }

    for file in search_files(base_dir):
        current_items_found = {}
        all_found_items[extract_filename(file)] = current_items_found
        current_items_found['cert_fips_id'] = extract_filename(file)
        initialize_entry(current_items_found)
        text = extract_certificates.load_cert_html_file(file)
        soup = BeautifulSoup(text, 'html.parser')
        print(file)
        for div in soup.find_all('div', class_='row padrow'):
            title = div.find('div', class_='col-md-3').text.strip()
            content = div.find('div', class_='col-md-9').text.strip()

            if title in pairs:
                if 'algorithms' not in pairs[title]:
                    content = content.replace('\n', '').replace('\t', '').replace('    ', ' ')
                if 'date' in pairs[title]:
                    current_items_found[pairs[title]] = content.split(';')
                elif 'caveat' in pairs[title]:
                    current_items_found[pairs[title]] = content
                    current_items_found['fips_mentioned_certs'] += parse_caveat(content)
                elif 'algorithms' in pairs[title]:
                    current_items_found['fips_algorithms'] += parse_table(content)
                elif 'tested_conf' in pairs[title]:
                    current_items_found[pairs[title]] = [x.text for x in
                                                         div.find('div', class_='col-md-9').find_all('li')]
                else:
                    current_items_found[pairs[title]] = content

        for div in soup.find_all('div', class_='panel panel-default')[1:]:
            if div.find('h4', class_='panel-title').text == 'Vendor':
                current_items_found['fips_vendor'] = div.find('div', 'panel-body').find('a').text
                if current_items_found['fips_vendor'] == '':
                    print("WARNING: NO VENDOR FOUND", file)

            if div.find('h4', class_='panel-title').text == 'Lab':
                current_items_found['fips_lab'] = list(div.find('div', 'panel-body').children)[0].strip()
                if current_items_found['fips_lab'] == '':
                    print("WARNING: NO LAB FOUND", file)

    if dump_to_file:
        with open(output_file, 'w', errors=FILE_ERRORS_STRATEGY) as write_file:
            json.dump(all_found_items, write_file, indent=4, sort_keys=True)

    return all_found_items


def get_dot_graph(found_items, output_file_name):
    """
    Function that plots .dot graph of dependencies between certificates
    Certificates with at least one dependency are displayed in "{output_file_name}connections.pdf", remaining
    certificates are displayed in {output_file_name}single.pdf
    :param found_items: Dictionary of all found items generated in main()
    :param output_file_name: prefix to "connections", "connections.pdf", "single" and "single.pdf"
    """
    dot = Digraph(comment='Certificate ecosystem')
    single_dot = Digraph(comment='Modules with no dependencies')
    single_dot.attr('graph', label='Single nodes', labelloc='t', fontsize='30')
    single_dot.attr('node', style='filled')
    dot.attr('graph', label='Dependencies', labelloc='t', fontsize='30')
    dot.attr('node', style='filled')

    def found_interesting_cert(current_key):
        if found_items[current_key]['fips_vendor'] == highlighted_vendor:
            dot.attr('node', color='red')
            if found_items[current_key]['fips_status'] == 'Revoked':
                dot.attr('node', color='grey32')
            if found_items[current_key]['fips_status'] == 'Historical':
                dot.attr('node', color='gold3')
        if found_items[current_key]['fips_vendor'] == "SUSE, LLC":
            dot.attr('node', color='lightblue')

    def color_check(current_key):
        dot.attr('node', color='lightgreen')
        if found_items[current_key]['fips_status'] == 'Revoked':
            dot.attr('node', color='lightgrey')
        if found_items[current_key]['fips_status'] == 'Historical':
            dot.attr('node', color='gold')
        found_interesting_cert(current_key)
        dot.node(current_key, label=current_key + '\n' + found_items[current_key]['fips_vendor'] +
                                    ('\n' + found_items[current_key]['fips_module_name']
                                     if 'fips_module_name' in found_items[current_key] else ''))

    keys = 0
    edges = 0

    highlighted_vendor = 'Red Hat®, Inc.'
    for key in found_items:
        if key != 'Not found' and found_items[key]['file_status']:
            if found_items[key]['Connections']:
                color_check(key)
                keys += 1
            else:
                single_dot.attr('node', color='lightblue')
                found_interesting_cert(key)
                single_dot.node(key, label=key + '\n' + found_items[key]['fips_vendor'] + ('\n' + found_items[key][
                    'fips_module_name'] if 'fips_module_name' in found_items[key] else ''))

    for key in found_items:
        if key != 'Not found' and found_items[key]['file_status']:
            for conn in found_items[key]['Connections']:
                color_check(conn)
                dot.edge(key, conn)
                edges += 1

    print(f"rendering {keys} keys and {edges} edges")

    dot.render(str(output_file_name) + '_connections', view=True)
    single_dot.render(str(output_file_name) + '_single', view=True)


def remove_algorithms_from_extracted_data(items, html):
    """
    Function that removes all found certificate IDs that are matching any IDs labeled as algorithm IDs
    :param items: All keyword items found in pdf files
    :param html: All items extracted from html files
    """
    for file_name in items:
        items[file_name]['file_status'] = True
        html[file_name]['file_status'] = True
        if html[file_name]['fips_mentioned_certs']:
            for item in html[file_name]['fips_mentioned_certs']:
                items[file_name]['rules_cert_id'].update(item)

        for rule in items[file_name]['rules_cert_id']:
            to_pop = set()
            rr = re.compile(rule)
            for cert in items[file_name]['rules_cert_id'][rule]:
                for alg in items[file_name]['rules_fips_algorithms']:
                    for found in items[file_name]['rules_fips_algorithms'][alg]:
                        if rr.search(found) and rr.search(cert) and rr.search(found).group('id') == rr.search(
                                cert).group('id'):
                            to_pop.add(cert)
            for r in to_pop:
                items[file_name]['rules_cert_id'][rule].pop(r, None)

            items[file_name]['rules_cert_id'][rule].pop(
                html[file_name]['cert_fips_id'], None)


def validate_results(items, html):
    """
    Function that validates results and finds the final connection output
    :param items: All keyword items found in pdf files
    :param html: All items extracted from html files - this is where we store connections
    """
    broken_files = set()
    for file_name in items:
        for rule in items[file_name]['rules_cert_id']:
            for cert in items[file_name]['rules_cert_id'][rule]:
                cert_id = ''.join(filter(str.isdigit, cert))

                if cert_id == '' or cert_id not in html:
                    # TEST
                    # if cert_id == '' or int(cert_id) > 3730:
                    broken_files.add(file_name)
                    items[file_name]['file_status'] = False
                    html[file_name]['file_status'] = False
                    break
    if broken_files:
        print("WARNING: CERTIFICATE FILES WITH WRONG CERTIFICATES PARSED")
        print(*sorted(list(broken_files)), sep='\n')
        print("... skipping these...")
        print("Total non-analyzable files:", len(broken_files))

    for file_name in items:
        html[file_name]['Connections'] = []
        if not items[file_name]['file_status']:
            continue
        if items[file_name]['rules_cert_id'] == {}:
            continue
        for rule in items[file_name]['rules_cert_id']:
            for cert in items[file_name]['rules_cert_id'][rule]:
                cert_id = ''.join(filter(str.isdigit, cert))
                if cert_id not in html[file_name]['Connections']:
                    html[file_name]['Connections'].append(cert_id)


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


def extract_page_number(txt: str) -> Optional[str]:
    """
    Parses chunks of text that are supposed to be mentioning table and having a footer
    :param txt: input chunk
    :return: page number
    """
    # Page # of #
    m = re.findall(r"(?P<pattern>(?:[Pp]age) (?P<page_num>\d+)(?: of \d+))", txt)
    if m:
        return m[-1][-1]
    # Page #
    m = re.findall(r"(?P<pattern>(?:[Pp]age) (?P<page_num>\d+)(?: of \d+)?)", txt)
    if m:
        return m[-1][-1]
    # # of #
    m = re.findall(r"(?P<pattern>(?:[Pp]age)? ?(?P<page_num>\d+)(?: of \d+))", txt)
    if m:
        return m[-1][-1]
    # number alone
    m = re.findall(r"(?P<pattern>(?:[Pp]age)? ?(?P<page_num>\d+)(?: of \d+)?)", txt)
    return m[-1][-1] if m else None


def find_tables_iterative(file_text: str) -> List[int]:
    current_page = 1
    pages = []
    for line in file_text.split('\n'):
        if '\f' in line:
            current_page += 1
        if line.startswith('Table') or line.startswith('Exhibit'):
            print(line)
            print(current_page)
            pages.append(current_page)

    return pages


def find_footers(txt):
    footer_regex = re.compile(
        r"(?:Table[^\f]*)(?P<first>^[\S\t ]*$)\n(?P<second>(\f[ \t\S]+)$)(?P<third>\n^[ \t\S]+?$)?",
        re.MULTILINE)

    # We have 2 groups, one is optional - trying to parse 2 lines (just in case)
    footer1 = [m.group('first') for m in footer_regex.finditer(txt)]
    footer2 = [m.group('second') for m in footer_regex.finditer(txt)]
    footer3 = [m.group('third') for m in footer_regex.finditer(txt)]

    # if len(footer2) < len(footer1):
    #     footer2 += [''] * (len(footer1) - len(footer2))

    # zipping them together
    footer_complete = [m[0] + m[1] + m[2] for m in zip(footer1, footer2, footer3) if
                       m[0] is not None and m[1] is not None and m[2] is not None]

    # removing None and duplicates
    footers = [extract_page_number(x) for x in footer_complete]
    footers = list(dict.fromkeys([x for x in footers if x is not None and 0 < int(x) < num_pages]))
    print(footers)
    if footers:
        return footers


def find_tables(txt, file_name, num_pages):
    """
    Function that tries to pages in security policy pdf files, where it's possible to find a table containing
    algorithms
    :param txt: file in .txt format (output of pdftotext)
    :param file_name: name of the file
    :param num_pages: number of pages in pdf
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


def repair_pdf_page_count(file: str) -> int:
    """
    Some pdfs can't be opened by PyPDF2 - opening them with pikepdf and then saving them fixes this issue.
    By opening this file in a pdf reader, we can already extract number of pages
    :param file: file name
    :return: number of pages in pdf file
    """
    pdf = pikepdf.Pdf.open(file, allow_overwriting_input=True)
    pdf.save(file)
    return len(pdf.pages)


def extract_certs_from_tables(list_of_files, html_items):
    """
    Function that extracts algorithm IDs from tables in security policies files.
    :param list_of_files: iterable containing all files to parse
    :param html_items: dictionary created by main() containing data extracted from html pages
    :return: list of files that couldn't have been decoded
    """
    not_decoded = []
    for cert_file in list_of_files:
        if '.txt' not in cert_file:
            continue

        if html_items[extract_filename(cert_file[:-8])]['tables_done']:
            continue

        with open(cert_file, 'r') as f:
            try:
                pages = repair_pdf_page_count(cert_file[:-4])
            except pikepdf._qpdf.PdfError:
                not_decoded.append(cert_file)
                continue
            tables = find_tables(f.read(), cert_file, pages)

        # If we find any tables with page numbers, we process them
        if tables:
            lst = []
            print("~~~~~~~~~~~~~~~", cert_file, "~~~~~~~~~~~~~~~~~~~~~~~")

            try:
                data = read_pdf(cert_file[:-4], pages=tables, silent=True)
            except Exception:
                not_decoded.append(cert_file)
                continue

            # find columns with cert numbers
            for df in data:
                for col in range(len(df.columns)):
                    if 'cert' in df.columns[col].lower() or 'algo' in df.columns[col].lower():
                        lst += parse_algorithms(df.iloc[:, col].to_string(index=False), True)

                # Parse again if someone picks not so descriptive column names
                lst += parse_algorithms(df.to_string(index=False))
            if lst:
                if 'fips_algorithms' not in html_items[extract_filename(cert_file[:-8])]:
                    html_items[extract_filename(cert_file[:-8])]['fips_algorithms'] = lst
                else:
                    html_items[extract_filename(cert_file[:-8])]['fips_algorithms'] += lst

        html_items[extract_filename(cert_file[:-8])]['tables_done'] = True
    return not_decoded


@click.command()
@click.argument("directory", required=True, type=str)
@click.option("--do-download-meta", "do_download_meta", is_flag=True)
@click.option("--do-download-certs", "do_download_certs", is_flag=True)
@click.option("-t", "--threads", "threads", type=int, default=4)
def main(directory, do_download_meta: bool, do_download_certs: bool, threads: int):
    start = time.time()
    directory = Path(directory)
    web_dir = directory / "web"
    fragments_dir = directory / "fragments"
    results_dir = directory / "results"
    policies_dir = directory / "security_policies"

    directory.mkdir(parents=True, exist_ok=True)
    web_dir.mkdir(parents=True, exist_ok=True)
    fragments_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)
    policies_dir.mkdir(parents=True, exist_ok=True)

    if do_download_meta:
        download_fips_web(web_dir)

    if do_download_certs:
        download_fips(web_dir, policies_dir, threads)

    files_to_load = [
        results_dir / 'fips_data_keywords_all.json',
        results_dir / 'fips_html_all.json'
    ]

    for file in files_to_load:
        if not os.path.isfile(file):
            fips_items = fips_search_html(web_dir,
                                          results_dir / 'fips_html_all.json', True)
            items = extract_certificates.extract_certificates_keywords(
                policies_dir,
                fragments_dir, 'fips', fips_items=fips_items,
                should_censure_right_away=True)
            with open(results_dir / 'fips_data_keywords_all.json', 'w') as f:
                json.dump(items, f, indent=4, sort_keys=True)
            break

    print("EXTRACTION DONE")
    items, html = load_json_files(files_to_load)

    print("FINDING TABLES")
    not_decoded = extract_certs_from_tables(search_files(policies_dir), html)

    print("NOT DECODED:", not_decoded)
    with open(results_dir / 'broken_files.json', 'w') as f:
        json.dump(not_decoded, f)

    print("REMOVING ALGORITHMS")
    remove_algorithms_from_extracted_data(items, html)

    print("VALIDATING RESULTS")
    validate_results(items, html)
    with open(results_dir / 'fips_html_all.json', 'w') as f:
        json.dump(html, f, indent=4, sort_keys=True)
    print("PLOTTING GRAPH")
    get_dot_graph(html, results_dir / 'output')
    end = time.time()
    print("TIME:", end - start)


if __name__ == '__main__':
    main()
