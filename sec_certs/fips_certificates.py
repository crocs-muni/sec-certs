#!/usr/bin/env python3
import json
import os
import re
import time

from graphviz import Digraph
from PyPDF2 import PdfFileReader, utils
import pikepdf
# from camelot import read_pdf
from tabula import read_pdf

import extract_certificates
from process_certificates import load_json_files
from cert_rules import rules_fips_htmls as RE_FIPS_HTMLS

FILE_ERRORS_STRATEGY = extract_certificates.FILE_ERRORS_STRATEGY
FIPS_BASE_URL = 'https://csrc.nist.gov'
FIPS_MODULE_URL = 'https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/'
FIPS_RESULTS_DIR = '/home/stan/sec-certs/fips_results/'
FIPS_BASE_DIR = '/home/stan/sec-certs/files/fips/'
SECURITY_POLICIES_DIR = '/home/stan/sec-certs/files/fips/security_policies/'


def extract_filename(file):
    return os.path.splitext(os.path.basename(file))[0]


def parse_ul(text):
    p = re.compile(r"<li>(.*?)<\/li>")
    return p.findall(text)


def parse_table(text):
    items_found_all = []

    # find <tr>, in that look for "text-nowrap" and look if there is a cert mentioned
    tr_pattern = re.compile(r"<tr>([\s\S]*?)<\/tr>")
    name_pattern = re.compile(r"wrap\">(?P<name>[\s\S]*?)<\/td>")
    cert_pattern_found = re.compile(r"<td>[ \S]*?#[ \S]*?\d+[ \S]*?<\/td>")
    cert_pattern_localize = re.compile(r"#?[ \S]*?(?P<cert>\d+)")

    for tr_match in tr_pattern.finditer(text):
        items_found = {}
        current_tr = tr_match.group()
        items_found['Name'] = name_pattern.search(current_tr).group('name')
        cert_line = cert_pattern_found.search(current_tr)

        if cert_line is None:
            items_found['Certificate'] = ['Not found']
        else:
            items_found['Certificate'] = ['#' + x.group('cert') for x in cert_pattern_localize.finditer(
                cert_line.group())]

        items_found_all.append(items_found)

    return items_found_all


def parse_algorithms(text, in_table=False):
    # print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    # print()
    # print(text)
    items_found = []
    for m in re.finditer(r"(?:#{}\s?|Cert\.?[^. ]*?\s?)(?:[Cc]\s)?(?P<id>\d+)".format('?' if in_table else ''), text):
        items_found.append({'Certificate': m.group()})

    return items_found


def parse_caveat(text):
    items_found = []

    for m in re.finditer(r"(?:#\s?|Cert\.?(?!.\s)\s?|Certificate\s?)(?P<id>\d+)", text):
        items_found.append({r"(?:#\s?|Cert\.?(?!.\s)\s?|Certificate\s?)(?P<id>\d+?})": {m.group(): {'count': 1}}})

    return items_found


def initialize_entry(input_dictionary):
    input_dictionary['fips_exceptions'] = []
    input_dictionary['fips_tested_conf'] = []

    input_dictionary['fips_algorithms'] = []
    input_dictionary['fips_caveat'] = []
    input_dictionary['tables_done'] = False


def fips_search_html(base_dir, output_file, dump_to_file=False):
    """fips_search_html.

    :param base_dir: directory to search for html files
    :param output_file: file to dump json to
    :param dump_to_file: True/False
    """

    all_found_items = {}

    for file in extract_certificates.search_files(base_dir):
        items_found = {}
        initialize_entry(items_found)
        text = extract_certificates.load_cert_html_file(file)
        filename = os.path.splitext(os.path.basename(file))[0]
        all_found_items[filename] = items_found
        items_found['cert_fips_id'] = filename

        for rule in RE_FIPS_HTMLS:
            m = re.search(rule, text)
            if m is None:
                # print("ERROR: For rule {} nothing found in file {}.".format(rule, file))
                continue

            group_dict = m.groupdict()
            key = list(group_dict)

            # <ul>
            if key[0] == 'fips_exceptions' or key[0] == 'fips_tested_conf':
                items_found[key[0]] = parse_ul(group_dict[key[0]])

            # <table>
            elif key[0] == 'fips_algorithms':
                if 'fips_algorithms' not in items_found:
                    items_found['fips_algorithms'] = parse_table(group_dict[key[0]])
                else:
                    items_found['fips_algorithms'] += parse_table(
                        group_dict[key[0]])

            # allowed algorithms
            elif key[0] == 'fips_allowed_algorithms':
                if 'fips_algorithms' not in items_found:
                    items_found['fips_algorithms'] = parse_algorithms(
                        group_dict[key[0]])
                else:
                    items_found['fips_algorithms'] += parse_algorithms(
                        group_dict[key[0]])

            # certificates in Caveat
            elif key[0] == 'fips_caveat':
                items_found['fips_mentioned_certs'] = parse_caveat(group_dict[key[0]])

            # there are usually multiple dates separated by ";"
            elif 'date' in key[0]:
                items_found[key[0]] = group_dict[key[0]].replace('\n', '').replace(
                    '\t', '').replace('  ', ' ').strip().split(';')

            else:
                items_found[key[0]] = group_dict[key[0]].replace(
                    '\n', '').replace('\t', '').replace('  ', ' ').strip()

    if dump_to_file:
        with open(output_file, 'w', errors=FILE_ERRORS_STRATEGY) as write_file:
            json.dump(all_found_items, write_file, indent=4, sort_keys=True)

    return all_found_items


def get_dot_graph(found_items, output_file_name):
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

    print("rendering {} keys and {} edges".format(keys, edges))

    dot.render(output_file_name + 'connections', view=True)
    single_dot.render(output_file_name + 'single', view=True)


def remove_algorithms_from_extracted_data(items, html):
    for file_name in items:
        items[file_name]['file_status'] = True
        html[file_name]['file_status'] = True
        if 'fips_mentioned_certs' in html[file_name]:
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
    broken_files = set()
    for file_name in items:
        for rule in items[file_name]['rules_cert_id']:
            for cert in items[file_name]['rules_cert_id'][rule]:
                cert_id = ''.join(filter(str.isdigit, cert))

                if cert_id == '' or cert_id not in html:
                    broken_files.add(file_name)
                    items[file_name]['file_status'] = False
                    html[file_name]['file_status'] = False
                    break

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


count = 0


def parse_list_of_tables(txt):
    """
    Parses list of tables from function find_tables(), finds ones that mention algorithms
    :param txt: chunk of text
    :return: list of all pages mentioning algorithm table
    """
    rr = re.compile(r"^.+?(?:[Ff]unction|[Aa]lgorithm).+?(?P<page_num>\d+)$", re.MULTILINE)
    pages = set()
    for m in rr.finditer(txt):
        pages.add(m.group('page_num'))
    return pages


def extract_page_number(txt):
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


def find_tables(txt, file_name, num_pages):
    global count

    # Look for "List of Tables", where we can find exactly tables with page num
    tables_regex = re.compile(r"^(?:(?:[Tt]able\s|[Ll]ist\s)(?:[Oo]f\s))[Tt]ables[\s\S]+?\f", re.MULTILINE)
    table = tables_regex.search(txt)
    if table:
        count += 1
        rb = parse_list_of_tables(table.group())
        if rb:
            return list(rb)
        return None

    # Otherwise look for "Table" in text and \f representing footer, then extract page number from footer
    print("~" * 20, file_name, '~' * 20)
    footer_regex = re.compile(r"(?:Table[^\f]*)(?P<first>^[\S\t ]*$)\n(?P<second>(\f[ \t\S]+)$)(?P<third>\n^[ \t\S]+?$)?",
                              re.MULTILINE)

    # We have 2 groups, one is optional - trying to parse 2 lines (just in case)
    footer1 = [m.group('first') for m in footer_regex.finditer(txt)]
    footer2 = [m.group('second') for m in footer_regex.finditer(txt)]
    footer3 = [m.group('third') for m in footer_regex.finditer(txt)]

    # if len(footer2) < len(footer1):
    #     footer2 += [''] * (len(footer1) - len(footer2))

    # zipping them together
    footer_complete = [m[0] + m[1] + m[2] for m in zip(footer1, footer2, footer3) if m[0] is not None and m[1] is not None and m[2] is not None]

    # removing None and duplicates
    footers = [extract_page_number(x) for x in footer_complete]
    footers = list(dict.fromkeys([x for x in footers if x is not None and 0 < int(x) < num_pages]))
    print(footers)
    if footers:
        return footers


def repair_pdf_page_count(file):
    pdf = pikepdf.Pdf.open(file, allow_overwriting_input=True)
    pdf.save(file)
    return len(pdf.pages)


def extract_certs_from_tables(list_of_files, html_items):
    global count

    not_decoded = []
    for REDHAT_FILE in list_of_files:
        if '.txt' not in REDHAT_FILE:
            continue

        if html_items[extract_filename(REDHAT_FILE[:-8])]['tables_done']:
            continue

        with open(REDHAT_FILE, 'r') as f:
            try:
                pages = repair_pdf_page_count(REDHAT_FILE[:-4])
            except pikepdf._qpdf.PdfError:
                not_decoded.append(REDHAT_FILE)
                continue
            tables = find_tables(f.read(), REDHAT_FILE, pages)

        # If we find any tables with page numbers, we process them
        if tables:
            lst = []
            print("~~~~~~~~~~~~~~~", REDHAT_FILE, "~~~~~~~~~~~~~~~~~~~~~~~")

            try:
                data = read_pdf(REDHAT_FILE[:-4], pages=tables, silent=True)
            except Exception:
                not_decoded.append(REDHAT_FILE)
                continue

            # find columns with cert numbers
            for df in data:
                for col in range(len(df.columns)):
                    if 'cert' in df.columns[col].lower() or 'algo' in df.columns[col].lower():
                        lst += parse_algorithms(df.iloc[:, col].to_string(index=False), True)

                # Parse again if someone picks not so descriptive column names
                lst += parse_algorithms(df.to_string(index=False))
            if lst:
                if 'fips_algorithms' not in html_items[extract_filename(REDHAT_FILE[:-8])]:
                    html_items[extract_filename(REDHAT_FILE[:-8])]['fips_algorithms'] = lst
                else:
                    html_items[extract_filename(REDHAT_FILE[:-8])]['fips_algorithms'] += lst

        html_items[extract_filename(REDHAT_FILE[:-8])]['tables_done'] = True
    return not_decoded


def main():
    files_to_load = [
        FIPS_RESULTS_DIR + 'fips_data_keywords_all.json',
        FIPS_RESULTS_DIR + 'fips_html_all.json'
    ]

    for file in files_to_load:
        if not os.path.isfile(file):
            fips_items = fips_search_html(os.path.join(FIPS_BASE_DIR, 'html'),
                                          os.path.join(FIPS_RESULTS_DIR,'fips_html_all.json'), True)
            items = extract_certificates.extract_certificates_keywords(
                os.path.join(FIPS_BASE_DIR, 'security_policies'),
                os.path.join(FIPS_BASE_DIR, 'fragments'), 'fips', fips_items=fips_items,
                should_censure_right_away=True, write_output_file=True)
            with open(FIPS_RESULTS_DIR + 'fips_data_keywords_all.json', 'w') as f:
                json.dump(items, f, indent=4, sort_keys=True)
            break

    print("EXTRACTION DONE")
    (items, html) = load_json_files(files_to_load)

    print("FINDING TABLES")
    not_decoded = extract_certs_from_tables(extract_certificates.search_files(SECURITY_POLICIES_DIR), html)

    print("NOT DECODED:", not_decoded)
    with open(FIPS_RESULTS_DIR + 'broken_files.json', 'w') as f:
        json.dump(not_decoded, f)

    print("REMOVING ALGORITHMS")
    remove_algorithms_from_extracted_data(items, html)

    print("VALIDATING RESULTS")
    validate_results(items, html)
    with open(FIPS_RESULTS_DIR + 'fips_html_all.json', 'w') as f:
        json.dump(html, f, indent=4, sort_keys=True)
    print("PLOTTING GRAPH")
    get_dot_graph(html, 'output')


if __name__ == '__main__':
    start = time.time()
    main()
    end = time.time()
    print("TIME:", end - start)
    print("COUNT:", count)
