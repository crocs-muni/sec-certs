#!/usr/bin/env python3
import json
import os
import re
import time
from pathlib import Path
from typing import Set, Optional, List, Dict
from bs4 import BeautifulSoup

from graphviz import Digraph
import click
import pikepdf
from tabula import read_pdf

from .download import download_fips_web, download_fips
from . import extract_certificates
from .files import load_json_files, FILE_ERRORS_STRATEGY, search_files

FIPS_BASE_URL = 'https://csrc.nist.gov'
FIPS_MODULE_URL = 'https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/'


def find_empty_pdfs(base_dir: Path) -> (List, List):
    missing = []
    not_available = []
    for i in range(1, 3725):
        if not (base_dir / f'{i}.pdf').exists():
            missing.append(i)
        elif os.path.getsize(base_dir / f'{i}.pdf') < 10000:
            not_available.append(i)
    return missing, not_available


def extract_filename(file: str) -> str:
    """
    Extracts filename from path
    @param file: UN*X path
    :return: filename without last extension
    """
    return os.path.splitext(os.path.basename(file))[0]


def initialize_entry(current_items_found):
    pass


def fips_search_html(base_dir: Path, output_file: str, dump_to_file: bool = False) -> Dict:
    all_found_items = {}

    # for file in search_files(base_dir):

    if dump_to_file:
        with open(output_file, 'w', errors=FILE_ERRORS_STRATEGY) as write_file:
            json.dump(all_found_items, write_file, indent=4, sort_keys=True)

    return all_found_items


def get_dot_graph(found_items: Dict, output_file_name: str):
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


def validate_results(items: Dict, html: Dict):
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
    pages = set()
    for line in file_text.split('\n'):
        if '\f' in line:
            current_page += 1
        if line.startswith('Table ') or line.startswith('Exhibit'):
            pages.add(current_page)
    if not pages:
        print('~' * 20, 'No pages found', '~' * 20)
    return list(pages)


def find_footers(txt: str, num_pages: int) -> Optional[List]:
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


def parse_algorithms(a, b=False):
    pass


def repair_pdf(file: Path):
    """
    Some pdfs can't be opened by PyPDF2 - opening them with pikepdf and then saving them fixes this issue.
    By opening this file in a pdf reader, we can already extract number of pages
    :param file: file name
    :return: number of pages in pdf file
    """
    pdf = pikepdf.Pdf.open(file, allow_overwriting_input=True)
    pdf.save(file)


def extract_certs_from_tables(list_of_files: List, html_items: Dict) -> List[Path]:
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
            tables = find_tables(f.read(), cert_file)

        # If we find any tables with page numbers, we process them
        if tables:
            lst = []
            print("~~~~~~~~~~~~~~~", cert_file, "~~~~~~~~~~~~~~~~~~~~~~~")
            try:
                data = read_pdf(cert_file[:-4], pages=tables, silent=True)
            except Exception:
                try:
                    repair_pdf(cert_file[:-4])
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

    missing, not_available = find_empty_pdfs(policies_dir)
    print(f"Missing security policies: Total {len(missing)}")
    print(f"Not available security policies: Total {len(not_available)}")
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
