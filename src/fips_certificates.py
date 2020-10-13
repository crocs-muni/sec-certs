import json
import os
import re
import subprocess
import threading

from graphviz import Digraph
from PyPDF2 import PdfFileReader
# from camelot import read_pdf
from tabula import read_pdf

import extract_certificates
from process_certificates import load_json_files

import time

FILE_ERRORS_STRATEGY = extract_certificates.FILE_ERRORS_STRATEGY
RE_LINK_TO_HTML = r'<a href=\"(\/projects.*?)\".*?>(\d+)<\/a>'
RE_FIPS_HTMLS = [
    r"module-name\">\s*(?P<fips_module_name>[^<]*)",
    r"module-standard\">\s*(?P<fips_standard>[^<]*)",
    r"Status[\s\S]*?\">\s*(?P<fips_status>[^<]*)",
    r"Sunset Date[\s\S]*?\">\s*(?P<fips_date_sunset>[^<]*)",
    r"Validation Dates[\s\S]*?\">\s*(?P<fips_date_validation>[^<]*)",
    r"Overall Level[\s\S]*?\">\s*(?P<fips_level>[^<]*)",
    r"Caveat[\s\S]*?\">\s*(?P<fips_caveat>[^<]*)",
    r"Security Level Exceptions[\s\S]*?\">\s*(?P<fips_exceptions><ul.*</ul>)",
    r"Module Type[\s\S]*?\">\s*(?P<fips_type>[^<]*)",
    r"Embodiment[\s\S]*?\">\s*(?P<fips_embodiment>[^<]*)",
    r"Tested Configuration[\s\S]*?\">\s*(?P<fips_tested_conf><ul.*</ul>)",
    r"FIPS Algorithms[\s\S]*?\">\s*(?P<fips_algorithms><tbody>[\s\S]*</tbody>)",
    r"Allowed Algorithms[\s\S]*?\">\s*(?P<fips_allowed_algorithms>[^<]*)",
    r"Software Versions[\s\S]*?\">\s*(?P<fips_software>[^<]*)",
    r"Product URL[\s\S]*?\">\s*<a href=\"(?P<fips_url>.*)\"",
    r"Vendor<\/h4>[\s\S]*?href=\".*?\">(?P<fips_vendor>.*?)<\/a>"
]
FIPS_BASE_URL = 'https://csrc.nist.gov'
FIPS_MODULE_URL = 'https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/'
FIPS_RESULTS_DIR = '/home/stan/sec-certs-master/fips_results/'
SECURITY_POLICIES_DIR = '/home/stan/sec-certs-master/files/fips/security_policies/'


def extract_filename(file):
    return os.path.splitext(os.path.basename(file))[0]


def generate_fips_basic_download_script():
    with open('download_fips_web.bat', 'w', errors=FILE_ERRORS_STRATEGY) as file:
        file.write(
            'curl "https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search'
            '/all" -o fips_modules_validated.html\n')


def generate_fips_download_script(file_name, fips_dir):
    """generate_fips_download_script.

    :param file_name: name of the download file
    :param fips_dir: directory for saved files
    """
    html_dir = fips_dir + '/html/'
    sp_dir = fips_dir + '/security_policies/'

    with open(file_name, 'w', errors=FILE_ERRORS_STRATEGY) as write_file:
        # make directories for both html and security policies, scraping in one go
        write_file.write('mkdir {}\n'.format(html_dir))
        write_file.write('mkdir {}\n\n'.format(sp_dir))

        for cert_id in range(1, 4001):
            write_file.write(
                'curl "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/{}" -o {}{}.html\n'.format(
                    cert_id, html_dir, cert_id))
            write_file.write(
                'curl "https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents'
                '/security-policies/140sp{}.pdf" -o {}{}.pdf\n'.format(
                    cert_id, sp_dir, cert_id))
            write_file.write("{} {}{}.pdf\n".format(
                extract_certificates.PDF2TEXT_CONVERT, sp_dir, cert_id))


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
    items_found = []
    for m in re.finditer(r"(?:#{}\s?|Cert\.?[^. ]*?\s?)(?:[Cc]\s)?(?P<id>\d+)".format('?' if in_table else ''), text):
        items_found.append({'Certificate': m.group()})

    return items_found


def parse_caveat(text):
    items_found = []

    for m in re.finditer(r"(?:#\s?|Cert\.?(?!.\s)\s?|Certificate\s?)(?P<id>\d+)", text):
        items_found.append({r"(?:#\s?|Cert\.?(?!.\s)\s?|Certificate\s?)(?P<id>\d+?})": {m.group(): {'count': 1}}})

    return items_found


def initialize_entry(dict):
    dict['fips_exceptions'] = []
    dict['fips_tested_conf'] = []

    dict['fips_algorithms'] = []
    dict['fips_caveat'] = []
    dict['tables_done'] = False


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

            gdict = m.groupdict()
            key = list(gdict)

            # <ul>
            if key[0] == 'fips_exceptions' or key[0] == 'fips_tested_conf':
                items_found[key[0]] = parse_ul(gdict[key[0]])

            # <table>
            elif key[0] == 'fips_algorithms':
                if 'fips_algorithms' not in items_found:
                    items_found['fips_algorithms'] = parse_table(gdict[key[0]])
                else:
                    items_found['fips_algorithms'] += parse_table(
                        gdict[key[0]])

            # allowed algorithms
            elif key[0] == 'fips_allowed_algorithms':
                if 'fips_algorithms' not in items_found:
                    items_found['fips_algorithms'] = parse_algorithms(
                        gdict[key[0]])
                else:
                    items_found['fips_algorithms'] += parse_algorithms(
                        gdict[key[0]])

            # certificates in Caveat
            elif key[0] == 'fips_caveat':
                items_found['fips_mentioned_certs'] = parse_caveat(gdict[key[0]])

            # there are usually multiple dates separated by ";"
            elif 'date' in key[0]:
                items_found[key[0]] = gdict[key[0]].replace('\n', '').replace(
                    '\t', '').replace('  ', ' ').strip().split(';')

            else:
                items_found[key[0]] = gdict[key[0]].replace(
                    '\n', '').replace('\t', '').replace('  ', ' ').strip()

    if dump_to_file:
        with open(output_file, 'w', errors=FILE_ERRORS_STRATEGY) as write_file:
            write_file.write(json.dumps(
                all_found_items, indent=4, sort_keys=True))

    return all_found_items


def get_dot_graph(found_items, output_file_name):
    dot = Digraph(comment='Certificate ecosystem')
    single_dot = Digraph(comment='Modules with no dependencies')
    single_dot.attr('graph', label='Single nodes', labelloc='t', fontsize='30')
    single_dot.attr('node', style='filled')
    dot.attr('graph', label='Dependencies', labelloc='t', fontsize='30')
    dot.attr('node', style='filled')

    keys = 0
    edges = 0

    highlighted_vendor = 'Red Hat®, Inc.'
    for key in found_items:
        if key != 'Not found' and found_items[key]['file_status']:
            if found_items[key]['Connections']:
                dot.attr('node', color='lightgreen')
                if found_items[key]['fips_status'] == 'Revoked':
                    dot.attr('node', color='lightgrey')
                if found_items[key]['fips_status'] == 'Historical':
                    dot.attr('node', color='gold')

                if found_items[key]['fips_vendor'] == highlighted_vendor:
                    dot.attr('node', color='red')
                    if found_items[key]['fips_status'] == 'Revoked':
                        dot.attr('node', color='grey32')
                    if found_items[key]['fips_status'] == 'Historical':
                        dot.attr('node', color='gold3')

                if found_items[key]['fips_vendor'] == "SUSE, LLC":
                    dot.attr('node', color='lightblue')
                dot.node(key, label=key + '\n' + found_items[key]['fips_vendor'] + ('\n' + found_items[key][
                    'fips_module_name'] if 'fips_module_name' in found_items[key] else ''))
                keys += 1
            else:
                single_dot.attr('node', color='lightblue')

                if found_items[key]['fips_vendor'] == highlighted_vendor:
                    single_dot.attr('node', color='red')

                    if found_items[key]['fips_status'] == 'Revoked':
                        dot.attr('node', color='grey32')
                    if found_items[key]['fips_status'] == 'Historical':
                        dot.attr('node', color='gold3')

                if found_items[key]['fips_vendor'] == "SUSE, LLC":
                    dot.attr('node', color='blue')
                single_dot.node(key, label=key + '\n' + found_items[key]['fips_vendor'] + ('\n' + found_items[key][
                    'fips_module_name'] if 'fips_module_name' in found_items[key] else ''))

    for key in found_items:
        if key != 'Not found' and found_items[key]['file_status']:
            for conn in found_items[key]['Connections']:
                dot.attr('node', color='lightgreen')
                if found_items[conn]['fips_status'] == 'Revoked':
                    dot.attr('node', color='lightgrey')
                if found_items[conn]['fips_status'] == 'Historical':
                    dot.attr('node', color='gold')

                if found_items[conn]['fips_vendor'] == highlighted_vendor:
                    dot.attr('node', color='red')
                    if found_items[conn]['fips_status'] == 'Revoked':
                        dot.attr('node', color='grey32')
                    if found_items[conn]['fips_status'] == 'Historical':
                        dot.attr('node', color='gold3')

                if found_items[conn]['fips_vendor'] == "SUSE, LLC":
                    dot.attr('node', color='lightblue')
                dot.node(conn, label=conn + '\n' + found_items[conn]['fips_vendor'] + ('\n' + found_items[conn][
                    'fips_module_name'] if 'fips_module_name' in found_items[conn] else ''))
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
    count = 0
    print("WARNING: CERTIFICATE FILES WITH WRONG CERTIFICATES PARSED")
    broken_files = set()
    for file_name in items:
        for rule in items[file_name]['rules_cert_id']:
            for cert in items[file_name]['rules_cert_id'][rule]:
                cert_id = ''.join(filter(str.isdigit, cert))

                if cert_id == '' or cert_id not in html:
                    broken_files.add(file_name)
                    items[file_name]['file_status'] = False
                    html[file_name]['file_status'] = False
                    count += 1
                    break

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


def main():
    files_to_load = [
        FIPS_RESULTS_DIR + 'fips_data_keywords_all.json',
        FIPS_RESULTS_DIR + 'fips_html_all.json'
    ]

    for file in files_to_load:
        if not os.path.isfile(file):
            fips_items = fips_search_html('/home/stan/sec-certs-master/files/fips/html/',
                                          FIPS_RESULTS_DIR + 'fips_html_all.json', True)
            items = extract_certificates.extract_certificates_keywords(
                '/home/stan/sec-certs-master/files/fips/security_policies/',
                '/home/stan/sec-certs-master/files/fips/fragments/', 'fips', fips_items=fips_items,
                should_censure_right_away=True, write_output_file=True)
            with open(FIPS_RESULTS_DIR + 'fips_data_keywords_all.json', 'w') as f:
                f.write(json.dumps(items, indent=4, sort_keys=True))
            break

    print("EXTRACTION DONE")
    (items, html) = load_json_files(files_to_load)

    print("FINDING TABLES")
    f_thread(extract_certificates.search_files(SECURITY_POLICIES_DIR), html)

    print("REMOVING ALGORITHMS")
    remove_algorithms_from_extracted_data(items, html)

    print("VALIDATING RESULTS")
    validate_results(items, html)
    with open(FIPS_RESULTS_DIR + 'fips_html_all.json', 'w') as f:
        f.write(json.dumps(html, indent=4, sort_keys=True))
    print("PLOTTING GRAPH")
    get_dot_graph(html, 'output')


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
    print(txt)
    m = re.findall(r"(?P<pattern>(?:[Pp]age) (?P<page_num>\d+)(?: of \d+))", txt)
    if m:
        return m[-1][-1]
    m = re.findall(r"(?P<pattern>(?:[Pp]age) (?P<page_num>\d+)(?: of \d+)?)", txt)
    if m:
        return m[-1][-1]
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
    # print("~" * 20, file_name, '~' * 20)
    # footer_regex = re.compile(r"(?:Table[^\f]*)(?P<first>(\f[ \t\S]+)$)(?P<second>\n^[ \t\S]+?$)?", re.MULTILINE)
    #
    # # We have 2 groups, one is optional - trying to parse 2 lines (just in case)
    # footer1 = [m.group('first') for m in footer_regex.finditer(txt)]
    # footer2 = [m.group('second') for m in footer_regex.finditer(txt)]
    # if len(footer2) < len(footer1):
    #     footer2 += [''] * (len(footer1) - len(footer2))
    #
    # # zipping them together
    # footer_complete = [m[0] + m[1] for m in zip(footer1, footer2)]
    #
    # # removing None and duplicates
    # footers = [extract_page_number(x) for x in footer_complete]
    # footers = list(dict.fromkeys([x for x in footers if x is not None and int(x) < num_pages]))
    #
    # print(footers)
    # if footers:
    #     return footers


def f_thread(list_of_files, html_items):
    global count
    # list_of_files = ['/home/stan/sec-certs-master/files/fips/security_policies/3245.pdf.txt']
    for REDHAT_FILE in list_of_files:
        if 'txt' not in REDHAT_FILE:
            continue

        if html_items[extract_filename(REDHAT_FILE[:-8])]['tables_done']:
            continue

        with open(REDHAT_FILE, 'r') as f:
            tables = find_tables(f.read(), REDHAT_FILE, PdfFileReader(open(REDHAT_FILE[:-4], 'rb')).getNumPages())

        # If we find any tables with page numbers, we process them
        if tables:
            lst = []
            print("~~~~~~~~~~~~~~~", REDHAT_FILE, "~~~~~~~~~~~~~~~~~~~~~~~")
            data = read_pdf(REDHAT_FILE[:-4], pages=tables)

            # find columns with cert numbers
            for df in data:
                for col in range(len(df.columns)):
                    if 'cert' in df.columns[col].lower() or 'algo' in df.columns[col].lower():
                        lst += parse_algorithms(df.iloc[:, col].to_string(index=False), True)
            if lst:
                if 'fips_algorithms' not in html_items[extract_filename(REDHAT_FILE[:-8])]:
                    html_items[extract_filename(REDHAT_FILE[:-8])]['fips_algorithms'] = lst
                else:
                    html_items[extract_filename(REDHAT_FILE[:-8])]['fips_algorithms'] += lst
        html_items[extract_filename(REDHAT_FILE[:-8])]['tables_done'] = True


if __name__ == '__main__':
    start = time.time()
    main()
    # f_thread(SECURITY_POLICIES_DIR, [])
    end = time.time()
    print("TIME:", end - start)
    print("COUNT:", count)
