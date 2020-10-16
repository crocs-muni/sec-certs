import csv
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote
from Levenshtein import distance

from cert_rules import rules
from pp_header_scan_source import *

# if True, then exception is raised when unexpect intermediate number is obtained
# Used as sanity check during development to detect sudden drop in number of extracted features
STOP_ON_UNEXPECTED_NUMS = False
APPEND_DETAILED_MATCH_MATCHES = False
VERBOSE = False

REGEXEC_SEP = '[ ,;\]”)(]'
LINE_SEPARATOR = ' '
FILE_ERRORS_STRATEGY = 'surrogateescape'
CC_WEB_URL = 'https://www.commoncriteriaportal.org'
PDF2TEXT_CONVERT = 'pdftotext -raw'

# LINE_SEPARATOR = ''  # if newline is not replaced with space, long string included in matches are found


def search_files(folder):
    for root, dirs, files in os.walk(folder):
        yield from [os.path.join(root, x) for x in files]


def extract_file_name_from_url(url):
    file_name = url[url.rfind('/') + 1:]
    file_name = file_name.replace('%20', ' ')
    return file_name


def is_in_dict(target_dict, path):
    current_level = target_dict
    for item in path:
        if item not in current_level:
            return False
        else:
            current_level = current_level[item]
    return True


def normalize_match_string(match):
    # normalize match
    match = match.strip()
    match = match.rstrip(']')
    match = match.rstrip('/')
    match = match.rstrip(';')
    match = match.rstrip('.')
    match = match.rstrip('”')
    match = match.rstrip('"')
    match = match.rstrip(':')
    # TODO check if needed
    match = match.rstrip(')')
    match = match.rstrip('(')
    match = match.rstrip(',')
    match = match.replace('  ', ' ')  # two spaces into one

    return match


def check_if_new_or_same(target_dict, target_key, new_value):
    if target_key in target_dict.keys():
        if target_dict[target_key] != new_value:
            if STOP_ON_UNEXPECTED_NUMS:
                raise ValueError('ERROR: Stopping on unexpected intermediate numbers')


# check if actual header belongs to a PP  for witch we already found another header
# comparison of titles in lowercase on lehvenstein distance <= 2 if any
# comparison of PP ID if any
def check_if_same_header(items_found, m_dict):
    for header in items_found:

        if TAG_PP_TITLE in header and TAG_PP_TITLE in m_dict:
            if distance(header[TAG_PP_TITLE].lower(), normalize_match_string(m_dict[TAG_PP_TITLE].lower())) <= 2:
                return True

        if TAG_PP_ID in header and TAG_PP_ID in m_dict and header[TAG_PP_ID] == normalize_match_string(
                m_dict[TAG_PP_ID]):
            return True

    return False


def fix_pp_url(original_url):
    if original_url.find('/epfiles/') != -1:  # links to pp are incorrect - epfiles instead ppfiles
        original_url = original_url.replace('/epfiles/', '/ppfiles/')
    original_url = original_url.replace('http://', 'https://')
    original_url = original_url.replace(':443', '')
    original_url = original_url.replace(':80', '')
    return original_url


def extract_pp_metadata_csv(file_name):
    items_found_all = {}
    download_files_certs = []
    download_files_maintainance = []
    expected_columns = -1
    with open(file_name, encoding='cp1250') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        no_further_maintainance = True
        for row in csv_reader:
            if line_count == 0:
                expected_columns = len(row)
                line_count += 1
            else:
                if no_further_maintainance:
                    items_found = {}
                if len(row) == 0:
                    break
                if len(row) != expected_columns:
                    print(
                        'WARNING: Incorrect number of columns in row {} (likely separator , in item name), going to fix...'.format(
                            line_count))
                    # trying to fix
                    if len(row) == expected_columns + 2:
                        row[9] = row[9] + row[10] + row[11]
                        row[10] = row[12]
                        row[11] = row[13]
                        del row[13]
                        del row[12]

                # check if some maintainance reports (based on presence of maintainance date - row[8]) are present.
                # If yes, then extract these to list of updates
                if len(row[8]) > 0:
                    no_further_maintainance = False
                else:
                    no_further_maintainance = True

                index_next_item = -1
                check_if_new_or_same(items_found, 'scheme', normalize_match_string(row[index_next_item]))
                items_found['scheme'] = normalize_match_string(row[index_next_item])
                index_next_item += 1
                check_if_new_or_same(items_found, 'cc_category', normalize_match_string(row[index_next_item]))
                items_found['cc_category'] = normalize_match_string(row[index_next_item])
                index_next_item += 1
                check_if_new_or_same(items_found, 'cc_pp_name', normalize_match_string(row[index_next_item]))
                items_found['cc_pp_name'] = normalize_match_string(row[index_next_item])
                index_next_item += 1
                check_if_new_or_same(items_found, 'cc_pp_version', normalize_match_string(row[index_next_item]))
                items_found['cc_pp_version'] = normalize_match_string(row[index_next_item])
                index_next_item += 1
                check_if_new_or_same(items_found, 'cc_security_level', normalize_match_string(row[index_next_item]))
                items_found['cc_security_level'] = normalize_match_string(row[index_next_item])
                index_next_item += 1
                check_if_new_or_same(items_found, 'cc_certification_date', normalize_match_string(row[index_next_item]))
                items_found['cc_certification_date'] = normalize_match_string(row[index_next_item])
                index_next_item += 1
                check_if_new_or_same(items_found, 'cc_archived_date', normalize_match_string(row[index_next_item]))
                items_found['cc_archived_date'] = normalize_match_string(row[index_next_item])
                index_next_item += 1
                check_if_new_or_same(items_found, 'link_pp_report', normalize_match_string(row[index_next_item]))
                items_found['link_pp_report'] = normalize_match_string(row[index_next_item])
                items_found['link_pp_report'] = fix_pp_url(items_found['link_pp_report'])
                index_next_item += 1
                pp_report_file_name = extract_file_name_from_url(items_found['link_pp_report'])
                check_if_new_or_same(items_found, 'link_pp_document', normalize_match_string(row[index_next_item]))
                items_found['link_pp_document'] = normalize_match_string(row[index_next_item])
                items_found['link_pp_document'] = fix_pp_url(items_found['link_pp_document'])
                index_next_item += 1
                pp_document_file_name = extract_file_name_from_url(items_found['link_pp_document'])

                if 'maintainance_updates' not in items_found:
                    items_found['maintainance_updates'] = []

                maintainance = {}
                maintainance['cc_pp_maintainance_date'] = normalize_match_string(row[index_next_item])
                index_next_item += 1
                maintainance['cc_pp_maintainance_title'] = normalize_match_string(row[index_next_item])
                index_next_item += 1
                maintainance['cc_maintainance_report_link'] = normalize_match_string(row[index_next_item])
                maintainance['cc_maintainance_report_link'] = fix_pp_url(maintainance['cc_maintainance_report_link'])
                index_next_item += 1

                # add this maintainance to parent item only when not empty
                if len(maintainance['cc_pp_maintainance_title']) > 0:
                    items_found['maintainance_updates'].append(maintainance)

                if no_further_maintainance:
                    # prepare unique name for dictionary (file name is not enough as multiple records reference same cert)
                    pp_document_file_name = pp_document_file_name.replace('%20', ' ')
                    item_unique_name = pp_document_file_name
                    item_unique_name = '{}__{}'.format(pp_document_file_name, line_count)
                    if item_unique_name not in items_found_all.keys():
                        items_found_all[item_unique_name] = {}
                        items_found_all[item_unique_name]['csv_scan'] = items_found
                    else:
                        print('  ERROR: {} already in'.format(pp_document_file_name))
                        if STOP_ON_UNEXPECTED_NUMS:
                            raise ValueError('ERROR: Stopping as value is not unique')

                    # save download links for basic protection profile
                    download_files_certs.append((items_found['link_pp_report'], pp_report_file_name,
                                                 items_found['link_pp_document'], pp_document_file_name))
                    # save download links for maintainance updates protection profile
                    for item in items_found['maintainance_updates']:
                        if item['cc_maintainance_report_link'] != "":
                            pp_maintainainace_file_name = extract_file_name_from_url(
                                item['cc_maintainance_report_link'])
                            download_files_maintainance.append(
                                (item['cc_maintainance_report_link'], pp_maintainainace_file_name))

                line_count += 1

    return items_found_all, download_files_certs, download_files_maintainance


def generate_download_script_old(file_name, certs_dir, targets_dir, download_files_certs):
    with open(file_name, "w") as write_file:
        # certs files
        write_file.write('mkdir \"{}\"\n'.format(certs_dir))
        write_file.write('cd \"{}\"\n\n'.format(certs_dir))
        for cert in download_files_certs:
            write_file.write('curl \"{}\" -o \"{}\"\n'.format(cert[0], cert[1]))
            write_file.write('pdftotext -raw \"{}\"\n\n'.format(cert[1]))

        if len(cert) > 2:
            # security targets file
            write_file.write('\n\ncd ..\n')
            write_file.write('mkdir \"{}\"\n'.format(targets_dir))
            write_file.write('cd \"{}\"\n\n'.format(targets_dir))
            for cert in download_files_certs:
                write_file.write('curl \"{}\" -o \"{}\"\n'.format(cert[2], cert[3]))
                write_file.write('pdftotext -raw \"{}\"\n\n'.format(cert[3]))

    os.chmod(file_name, int('755', base=8))
    return file_name


def generate_download_script(file_name, certs_dir, targets_dir, base_url, download_files_certs):
    with open(file_name, "w", errors=FILE_ERRORS_STRATEGY) as write_file:
        # certs files
        if certs_dir != '':
            write_file.write('mkdir \"{}\"\n'.format(certs_dir))
            write_file.write('cd \"{}\"\n\n'.format(certs_dir))
        for cert in download_files_certs:
            # double %% is necessary to prevent replacement of %2 within script (second argument of script)
            file_name_short_web = cert[0].replace(' ', '%%20')

            if file_name_short_web.find(base_url) != -1:
                # base url already included
                write_file.write('curl \"{}\" -o \"{}\"\n'.format(file_name_short_web, cert[1]))
            else:
                # insert base url
                write_file.write('curl \"{}{}\" -o \"{}\"\n'.format(base_url, file_name_short_web, cert[1]))
            write_file.write('{} \"{}\"\n\n'.format(PDF2TEXT_CONVERT, cert[1]))

        if len(download_files_certs) > 0 and len(cert) > 2:
            # security targets file
            if targets_dir != '':
                write_file.write('\n\ncd ..\n')
                write_file.write('mkdir \"{}\"\n'.format(targets_dir))
                write_file.write('cd \"{}\"\n\n'.format(targets_dir))
            for cert in download_files_certs:
                # double %% is necessary to prevent replacement of %2 within script (second argument of script)
                file_name_short_web = cert[2].replace(' ', '%%20')
                try:
                    if file_name_short_web.find(base_url) != -1:
                    # base url already included
                        write_file.write('curl \"{}\" -o \"{}\"\n'.format(file_name_short_web, cert[3]))
                    else:
                        # insert base url
                        write_file.write('curl \"{}{}\" -o \"{}\"\n'.format(base_url, file_name_short_web, cert[3]))
                    write_file.write('{} \"{}\"\n\n'.format(PDF2TEXT_CONVERT, cert[3]))

                except UnicodeEncodeError as err:
                    print(err)


def extract_protectionprofiles_csv(base_dir, download_pps=False):
    print('*** Starting CSV scan ***')
    file_name = base_dir / 'cc_pp_active.csv'
    items_found_all_active, download_files_pp, download_files_pp_updates = extract_pp_metadata_csv(file_name)
    for item in items_found_all_active.keys():
        items_found_all_active[item]['csv_scan']['cert_status'] = 'active'

    script_path = generate_download_script(Path('download_active_pp.bat').absolute(),
                                           Path('../active_pp_report').absolute(),
                                           'active_pps', CC_WEB_URL,
                                           download_files_pp)

    if download_pps:
        subprocess.run([str(script_path)], shell=True, check=True)

    generate_download_script(Path('download_active_pp_updates.bat').absolute(),
                             Path('../active_pp_updates').absolute(),
                             'active_pp_updates', CC_WEB_URL,
                             download_files_pp_updates)

    file_name = base_dir / 'cc_pp_archived.csv'
    items_found_all_archived, download_files_pp, download_files_pp_updates = extract_pp_metadata_csv(file_name)
    for item in items_found_all_archived.keys():
        items_found_all_archived[item]['csv_scan']['cert_status'] = 'archived'

    generate_download_script(Path('download_archived_pp.bat').absolute(),
                             Path('../archived_pp_report').absolute(),
                             'archived_pps', CC_WEB_URL,
                             download_files_pp)
    generate_download_script(Path('download_archived_pp_updates.bat').absolute(),
                             Path('../archived_pp_updates').absolute(),
                             'archived_pp_updates', CC_WEB_URL,
                             download_files_pp_updates)

    items_found_all = {**items_found_all_active, **items_found_all_archived}
    with open("pp_data_csv_all.json", "w") as write_file:
        write_file.write(json.dumps(items_found_all, indent=4, sort_keys=True))

    print('\n\n')
    return items_found_all


def generate_basic_download_script():
    script_path = Path('../results/download_cc_web.bat')

    with open(script_path, 'w') as file:
        file.write('cd ..\n')
        file.write('mkdir pp_web\n')
        file.write('cd pp_web\n')
        file.write('curl \"https://www.commoncriteriaportal.org/products/\" -o cc_products_active.html\n')
        file.write(
            'curl \"https://www.commoncriteriaportal.org/products/index.cfm?archived=1\" -o cc_products_archived.html\n\n')

        file.write('curl \"https://www.commoncriteriaportal.org/labs/\" -o cc_labs.html\n')

        file.write(
            'curl \"https://www.commoncriteriaportal.org/products/certified_products.csv\" -o cc_products_active.csv\n')
        file.write(
            'curl \"https://www.commoncriteriaportal.org/products/certified_products-archived.csv\" -o cc_products_archived.csv\n\n')

        file.write('curl \"https://www.commoncriteriaportal.org/pps/\" -o cc_pp_active.html\n')
        file.write(
            'curl \"https://www.commoncriteriaportal.org/pps/collaborativePP.cfm?cpp=1\" -o cc_pp_collaborative.html\n')
        file.write('curl \"https://www.commoncriteriaportal.org/pps/index.cfm?archived=1\" -o cc_pp_archived.html\n\n')

        file.write('curl \"https://www.commoncriteriaportal.org/pps/pps.csv\" -o cc_pp_active.csv\n')
        file.write('curl \"https://www.commoncriteriaportal.org/pps/pps-archived.csv\" -o cc_pp_archived.csv\n\n')

    os.chmod(script_path, int('755', base=8))

    return script_path


def extract_protectionprofiles_frontpage(walk_dir):
    print('*** Starting PP frontpage header regex scan ***')
    pp_items_found, pp_files_without_match = search_pp_only_headers(walk_dir)

    print_no_hit_files(pp_files_without_match)

    print('\n*** Trying to search PP headers in PP header database ***')
    pp_items_found_db, pp_files_without_match = search_pp_only_headers_database(pp_files_without_match)
    pp_items_found.update(pp_items_found_db)

    print_no_hit_files(pp_files_without_match)

    # store results into file with fixed name and also with time appendix
    with open("pp_data_frontpage_all.json", "w") as write_file:
        write_file.write(json.dumps(pp_items_found, indent=4, sort_keys=True))

    print('\n\n')
    return pp_items_found


def load_cert_file(file_name, limit_max_lines=-1, line_separator=LINE_SEPARATOR):
    lines = []
    was_unicode_decode_error = False
    with open(file_name, 'r') as f:
        try:
            lines = f.readlines()
        except UnicodeDecodeError:
            f.close()
            was_unicode_decode_error = True
            print('  WARNING: UnicodeDecodeError, opening as utf8')

            with open(file_name, encoding="utf8") as f2:
                # coding failure, try line by line
                line = ' '
                while line:
                    try:
                        line = f2.readline()
                        lines.append(line)
                    except UnicodeDecodeError:
                        # ignore error
                        continue

    whole_text = ''
    whole_text_with_newlines = ''
    # we will estimate the line for searched matches
    # => we need to known how much lines were modified (removal of eoln..)
    line_length_compensation = 1 - len(LINE_SEPARATOR)  # for removed newline and for any added separator
    lines_included = 0
    for line in lines:
        if limit_max_lines != -1 and lines_included >= limit_max_lines:
            break

        whole_text_with_newlines += line
        line = line.replace('\n', '')
        whole_text += line
        whole_text += line_separator
        lines_included += 1

    return whole_text, whole_text_with_newlines, was_unicode_decode_error


def search_pp_only_headers(walk_dir):
    # LINE_SEPARATOR_STRICT = ' '
    # NUM_LINES_TO_INVESTIGATE = 15
    # rules_certificate_preface = [
    #     '(Common Criteria Protection Profile .+)?(BSI-PP-CC-.+?)Federal Office for Information Security',
    #     '(Protection Profile for the .+)?Schutzprofil für das .+?Certification-ID (BSI-CC-PP-[0-9]+?) ',
    #  #  'Protection Profile for the Security Module of a Smart Meter Mini-HSM (Mini-HSM Security Module PP) Schutzprofil für das Sicherheitsmodul des Smart Meter Mini-HSM  Mini-HSM SecMod-PP Version 1.0 – 23 June 2017 Certification-ID BSI-CC-PP-0095  Mini-HSM Security Module PP  Bundesamt für Sicherheit in der Informationstechnik'
    # ]

    items_found_all = {}
    files_without_match = []
    for file_name in search_files(walk_dir):
        if not os.path.isfile(file_name):
            continue
        file_ext = file_name[file_name.rfind('.'):]
        if file_ext != '.txt':
            continue
        print('*** {} ***'.format(file_name))

        #
        # Process page with more detailed protection profile info
        # PP Reference

        whole_text, whole_text_with_newlines, was_unicode_decode_error = load_cert_file(file_name)

        no_match_yet = True
        actual_header = -1
        found_header_start = []
        for rule in regex_rules:
            rule_and_sep = rule[1] + REGEXEC_SEP

            for m in re.finditer(rule_and_sep, whole_text):
                if no_match_yet:
                    items_found_all[file_name] = []
                    items_found = items_found_all[file_name]
                    no_match_yet = False

                # new header found, insert new schema
                if m.start(1) not in found_header_start and not check_if_same_header(items_found, m.groupdict()):
                    found_header_start.append(m.start(1))
                    items_found_all[file_name].append({})
                    actual_header += 1
                    items_found[actual_header][TAG_HEADER_MATCH_RULES] = []

                # insert rule if at least one match for it was found
                if rule[1] not in items_found[actual_header][TAG_HEADER_MATCH_RULES]:
                    items_found[actual_header][TAG_HEADER_MATCH_RULES].append(rule[1])

                groups_dict = m.groupdict()
                for key in groups_dict.keys():
                    if groups_dict[key] is not None:
                        set_match_string(items_found[actual_header], key, normalize_match_string(groups_dict[key]))

                registrator_tag = rule[0].value
                if rule[0] == HeaderType.ANSSI_BSI_COMMON.value:
                    registrator_tag = 'ANSSI' if 'ANSSI' in groups_dict[TAG_PP_REGISTRATOR] else 'BSI'

                set_match_string(items_found[actual_header], TAG_PP_REGISTRATOR_SIMPLIFIED, registrator_tag)

        if no_match_yet:
            files_without_match.append(file_name)

    with open("pp_data_header_regex_scan.json", "w") as write_file:
        write_file.write(json.dumps(items_found_all, indent=4, sort_keys=True))

    return items_found_all, files_without_match


# new approach, searching PP headers inside user-created database
def search_pp_only_headers_database(pp_files):
    items_found = {}
    files_without_match = []

    for file in pp_files:
        file_stem = Path(file).stem
        print('*** {} ***'.format(file))

        # TODO iterate over pp_header_db
        if file_stem in header_db_source:
            items_found[file] = header_db_source[file_stem]
        else:
            files_without_match.append(file)

    with open("pp_data_header_db_scan.json", "w") as write_file:
        write_file.write(json.dumps(items_found, indent=4, sort_keys=True))

    return items_found, files_without_match


def print_no_hit_files(files_without_match):
    print('\n*** Protection profiles without detected header ***')
    for file_name in files_without_match:
        print('No hits for {}'.format(file_name))
    print('Total no hits files: {}'.format(len(files_without_match)))
    print('\n**********************************')


def set_match_string(items, key_name, new_value):
    if key_name not in items.keys():
        items[key_name] = new_value
    else:
        old_value = items[key_name]
        if old_value != new_value:
            print(
                '  WARNING: values mismatch, key=\'{}\', old=\'{}\', new=\'{}\''.format(key_name, old_value, new_value))


def parse_cert_file(file_name, search_rules, limit_max_lines=-1, line_separator=LINE_SEPARATOR):
    whole_text, whole_text_with_newlines, was_unicode_decode_error = load_cert_file(file_name, limit_max_lines,
                                                                                    line_separator)

    # apply all rules
    items_found_all = {}
    for rule_group in search_rules.keys():
        if rule_group not in items_found_all:
            items_found_all[rule_group] = {}

        items_found = items_found_all[rule_group]

        for rule in search_rules[rule_group]:
            rule_and_sep = rule + REGEXEC_SEP

            for m in re.finditer(rule_and_sep, whole_text):
                # insert rule if at least one match for it was found
                if rule not in items_found:
                    items_found[rule] = {}

                match = m.group()
                match = normalize_match_string(match)

                if match not in items_found[rule]:
                    items_found[rule][match] = {}
                    items_found[rule][match][TAG_MATCH_COUNTER] = 0
                    if APPEND_DETAILED_MATCH_MATCHES:
                        items_found[rule][match][TAG_MATCH_MATCHES] = []
                    # else:
                    #    items_found[rule][match][TAG_MATCH_MATCHES] = ['List of matches positions disabled. Set APPEND_DETAILED_MATCH_MATCHES to True']

                items_found[rule][match][TAG_MATCH_COUNTER] += 1
                match_span = m.span()
                # estimate line in original text file
                # line_number = get_line_number(lines, line_length_compensation, match_span[0])
                # start index, end index, line number
                # items_found[rule][match][TAG_MATCH_MATCHES].append([match_span[0], match_span[1], line_number])
                if APPEND_DETAILED_MATCH_MATCHES:
                    items_found[rule][match][TAG_MATCH_MATCHES].append([match_span[0], match_span[1]])

    # highlight all found strings from the input text and store the rest
    for rule_group in items_found_all.keys():
        items_found = items_found_all[rule_group]
        for rule in items_found.keys():
            for match in items_found[rule]:
                whole_text_with_newlines = whole_text_with_newlines.replace(match, 'x' * len(
                    match))  # warning - if AES string is removed before AES-128, -128 will be left in text (does it matter?)

    return items_found_all, (whole_text_with_newlines, was_unicode_decode_error)


def estimate_cert_id(frontpage_scan, keywords_scan, file_name):
    # check if cert id was extracted from frontpage (most priority)
    frontpage_cert_id = ''
    if frontpage_scan != None:
        # TODO check if first header contains key 'cert_id', in case that we consider first header as some base,
        # otherwise iterate over all headers
        if 'cert_id' in frontpage_scan[0].keys():
            frontpage_cert_id = frontpage_scan['cert_id']

    keywords_cert_id = ''
    if keywords_scan != None:
        # find certificate ID which is the most common
        num_items_found_certid_group = 0
        max_occurences = 0
        items_found = keywords_scan['rules_cert_id']
        for rule in items_found.keys():
            for match in items_found[rule]:
                num_occurences = items_found[rule][match][TAG_MATCH_COUNTER]
                if num_occurences > max_occurences:
                    max_occurences = num_occurences
                    keywords_cert_id = match
                num_items_found_certid_group += num_occurences
        if VERBOSE:
            print('  -> most frequent cert id: {}, {}x'.format(keywords_cert_id, num_items_found_certid_group))

    # try to search for certificate id directly in file name - if found, higher priority
    filename_cert_id = ''
    if file_name != None:
        file_name_no_suff = file_name[:file_name.rfind('.')]
        file_name_no_suff = file_name_no_suff[file_name_no_suff.rfind('\\') + 1:]
        for rule in rules['rules_cert_id']:
            file_name_no_suff += ' '
            matches = re.findall(rule, file_name_no_suff)
            if len(matches) > 0:
                # we found cert id directly in name
                # print('  -> cert id found directly in certificate name: {}'.format(matches[0]))
                filename_cert_id = matches[0]

    if VERBOSE:
        print('Identified cert ids for {}:'.format(file_name))
        print('  frontpage_cert_id: {}'.format(frontpage_cert_id))
        print('  filename_cert_id: {}'.format(filename_cert_id))
        print('  keywords_cert_id: {}'.format(keywords_cert_id))

    if frontpage_cert_id != '':
        return frontpage_cert_id
    if filename_cert_id != '':
        return filename_cert_id
    if keywords_cert_id != '':
        return keywords_cert_id

    return ''


def extract_certificates_keywords(walk_dir, fragments_dir, file_prefix):
    all_items_found = {}
    cert_id = {}

    print('*** Starting keyword scan ***\n')

    fragments_dir.mkdir(exist_ok=True)

    for file_name in search_files(walk_dir):
        file_name_path = Path(file_name)

        if not file_name_path.is_file():
            continue

        if file_name_path.suffix != '.txt':
            continue

        print('*** {} ***'.format(file_name))

        # parse certificate, return all matches
        all_items_found[file_name], modified_cert_file = parse_cert_file(file_name, rules, -1)

        # try to establish the certificate id of the current certificate
        cert_id[file_name] = estimate_cert_id(None, all_items_found[file_name], file_name)

        # save report text with highlighted/replaced matches into \\fragments\\ directory
        target_file = str(fragments_dir / file_name_path.name)
        save_modified_cert_file(target_file, modified_cert_file[0], modified_cert_file[1])

    # store results into file with fixed name and also with time appendix
    with open("{}_data_keywords_all.json".format(file_prefix), "w") as write_file:
        write_file.write(json.dumps(all_items_found, indent=4, sort_keys=True))

    #print('\nTotal matches found in separate files:'.format(all))
    # print_total_matches_in_files(all_items_found_count)

    #print('\nFile name and estimated certificate ID:')
    #print_guessed_cert_id(cert_id)

    # depricated_print_dot_graph_keywordsonly(['rules_cert_id'], all_items_found[actual_header], cert_id, walk_dir, 'certid_graph_from_keywords.dot', True)

    total_items_found = 0
    for file_name in all_items_found:
        total_items_found += count_num_items_found(all_items_found[file_name])

    all_matches = []
    for file_name in all_items_found:
        for rule_group in all_items_found[file_name].keys():
            items_found = all_items_found[file_name][rule_group]
            for rule in items_found.keys():
                for match in items_found[rule]:
                    if match not in all_matches:
                        all_matches.append(match)

    print('*** Keyword matches ***')
    sorted_all_matches = sorted(all_matches)
    for match in sorted_all_matches:
        print(match)

    # verify total matches found
    print('\nTotal matches found: {}'.format(total_items_found))

    return all_items_found


def count_num_items_found(items_found_all):
    num_items_found = 0
    for rule_group in items_found_all.keys():
        items_found = items_found_all[rule_group]
        for rule in items_found.keys():
            for match in items_found[rule]:
                num_items_found += 1

    return num_items_found


def save_modified_cert_file(target_file, modified_cert_file_text, is_unicode_text):
    if is_unicode_text:
        write_file = open(target_file, "w", encoding="utf8")
    else:
        write_file = open(target_file, "w")

    try:
        write_file.write(modified_cert_file_text)
    except UnicodeEncodeError as e:
        write_file.close()
        print('UnicodeDecodeError while writing file fragments back')

    write_file.close()


def collate_certificates_data(all_html, all_csv, all_front, all_keywords, all_pdf_meta, file_name_key):
    print('\n\n*** Pairing results from different scans ***')

    file_name_to_html_name_mapping = {}
    for long_file_name in all_html.keys():
        short_file_name = long_file_name[long_file_name.rfind(os.sep) + 1:]
        if short_file_name != '':
            file_name_to_html_name_mapping[short_file_name] = long_file_name

    file_name_to_front_name_mapping = {}
    for long_file_name in all_front.keys():
        short_file_name = long_file_name[long_file_name.rfind(os.sep) + 1:]
        if short_file_name != '':
            file_name_to_front_name_mapping[short_file_name] = long_file_name

    file_name_to_keywords_name_mapping = {}
    for long_file_name in all_keywords.keys():
        short_file_name = long_file_name[long_file_name.rfind(os.sep) + 1:]
        if short_file_name != '':
            file_name_to_keywords_name_mapping[short_file_name] = [long_file_name, 0]

    file_name_to_pdfmeta_name_mapping = {}
    for long_file_name in all_pdf_meta.keys():
        short_file_name = long_file_name[long_file_name.rfind(os.sep) + 1:]
        if short_file_name != '':
            file_name_to_pdfmeta_name_mapping[short_file_name] = [long_file_name, 0]

    all_cert_items = all_csv
    # pair html data, csv data, front pages and keywords
    for file_name in all_csv.keys():
        pairing_found = False

        file_name_pdf = file_name[:file_name.rfind('__')]
        file_name_txt = file_name_pdf[:file_name_pdf.rfind('.')] + '.txt'
        # file_name_st = all_csv[file_name]['csv_scan']['link_security_target_file_name']
        if is_in_dict(all_csv, [file_name, 'csv_scan', 'link_security_target']):
            file_name_st = extract_file_name_from_url(all_csv[file_name]['csv_scan']['link_security_target'])
            file_name_st_txt = file_name_st[:file_name_st.rfind('.')] + '.txt'
        else:
            file_name_st_txt = 'security_target_which_doesnt_exists'

        # for file_and_id in all_html.keys():
        #     # in items extracted from html, names are in form of 'file_name.pdf__number'
        #     if file_and_id.find(file_name_pdf + '__') != -1:
        if 'processed' not in all_cert_items[file_name].keys():
            all_cert_items[file_name]['processed'] = {}
        pairing_found = True
        frontpage_scan = None
        keywords_scan = None

        if file_name_txt in file_name_to_html_name_mapping.keys():
            all_cert_items[file_name]['html_scan'] = all_html[file_name_to_html_name_mapping[file_name_txt][0]]
            file_name_to_html_name_mapping[file_name_txt][1] = 1  # was paired
        else:
            print('WARNING: Corresponding HTML report not found for CSV item {}'.format(file_name))
        if file_name_txt in file_name_to_front_name_mapping.keys():
            all_cert_items[file_name]['frontpage_scan'] = all_front[file_name_to_front_name_mapping[file_name_txt]]
            frontpage_scan = all_front[file_name_to_front_name_mapping[file_name_txt]]
        if file_name_txt in file_name_to_keywords_name_mapping.keys():
            all_cert_items[file_name]['keywords_scan'] = all_keywords[
                file_name_to_keywords_name_mapping[file_name_txt][0]]
            file_name_to_keywords_name_mapping[file_name_txt][1] = 1  # was paired
            keywords_scan = all_keywords[file_name_to_keywords_name_mapping[file_name_txt][0]]
        if file_name_st_txt in file_name_to_keywords_name_mapping.keys():
            all_cert_items[file_name]['st_keywords_scan'] = all_keywords[
                file_name_to_keywords_name_mapping[file_name_st_txt][0]]
            file_name_to_keywords_name_mapping[file_name_st_txt][1] = 1  # was paired
        if file_name_pdf in file_name_to_pdfmeta_name_mapping.keys():
            all_cert_items[file_name]['pdfmeta_scan'] = all_pdf_meta[
                file_name_to_pdfmeta_name_mapping[file_name_pdf][0]]
            file_name_to_pdfmeta_name_mapping[file_name_pdf][1] = 1  # was paired
        else:
            print('ERROR: File {} not found in pdfmeta scan'.format(file_name_pdf))
        all_cert_items[file_name]['processed']['cert_id'] = estimate_cert_id(frontpage_scan, keywords_scan, file_name)

    # pair pairing in maintainance updates
    for file_name in all_csv.keys():
        pairing_found = False

        # process all maintainance updates
        for update in all_cert_items[file_name]['csv_scan']['maintainance_updates']:

            file_name_pdf = extract_file_name_from_url(update['cc_maintainance_report_link'])
            file_name_txt = file_name_pdf[:file_name_pdf.rfind('.')] + '.txt'

            if is_in_dict(update, ['cc_maintainance_st_link']):
                file_name_st = extract_file_name_from_url(update['cc_maintainance_st_link'])
                file_name_st_pdf = file_name_st
                file_name_st_txt = ''
                if len(file_name_st) > 0:
                    file_name_st_txt = file_name_st[:file_name_st.rfind('.')] + '.txt'
            else:
                file_name_st_pdf = 'file_name_which_doesnt_exists'
                file_name_st_txt = 'file_name_which_doesnt_exists'

            for file_and_id in all_keywords.keys():
                file_name_keyword_txt = file_and_id[file_and_id.rfind('\\') + 1:]
                # in items extracted from html, names are in form of 'file_name.pdf__number'
                if file_name_keyword_txt == file_name_txt:
                    pairing_found = True
                    if file_name_txt in file_name_to_keywords_name_mapping.keys():
                        update['keywords_scan'] = all_keywords[file_name_to_keywords_name_mapping[file_name_txt][0]]
                        if file_name_to_keywords_name_mapping[file_name_txt][1] == 1:
                            print('WARNING: {} already paired'.format(
                                file_name_to_keywords_name_mapping[file_name_txt][0]))
                        file_name_to_keywords_name_mapping[file_name_txt][1] = 1  # was paired

                if file_name_keyword_txt == file_name_st_txt:
                    if file_name_st_txt in file_name_to_keywords_name_mapping.keys():
                        update['st_keywords_scan'] = all_keywords[
                            file_name_to_keywords_name_mapping[file_name_st_txt][0]]
                        if file_name_to_keywords_name_mapping[file_name_st_txt][1] == 1:
                            print('WARNING: {} already paired'.format(
                                file_name_to_keywords_name_mapping[file_name_st_txt][0]))
                        file_name_to_keywords_name_mapping[file_name_st_txt][1] = 1  # was paired

            if not pairing_found:
                print('WARNING: Corresponding keywords pairing not found for maintaince item {}'.format(file_name))

            for file_and_id in file_name_to_pdfmeta_name_mapping.keys():
                file_name_pdf = file_and_id[file_and_id.rfind('\\') + 1:]
                file_name_pdfmeta_txt = file_name_pdf[:file_name_pdf.rfind('.')] + '.txt'
                # in items extracted from html, names are in form of 'file_name.pdf__number'
                if file_name_pdfmeta_txt == file_name_txt:
                    pairing_found = True
                    if file_name_pdf in file_name_to_pdfmeta_name_mapping.keys():
                        update['pdfmeta_scan'] = all_pdf_meta[file_name_to_pdfmeta_name_mapping[file_name_pdf][0]]
                        if file_name_to_pdfmeta_name_mapping[file_name_pdf][1] == 1:
                            print('WARNING: {} already paired'.format(
                                file_name_to_pdfmeta_name_mapping[file_name_pdf][0]))
                        file_name_to_pdfmeta_name_mapping[file_name_pdf][1] = 1  # was paired

                if file_name_pdfmeta_txt == file_name_st_txt:
                    if file_name_st_pdf in file_name_to_pdfmeta_name_mapping.keys():
                        update['st_pdfmeta_scan'] = all_pdf_meta[file_name_to_pdfmeta_name_mapping[file_name_st_pdf][0]]
                        if file_name_to_pdfmeta_name_mapping[file_name_st_pdf][1] == 1:
                            print('WARNING: {} already paired'.format(
                                file_name_to_pdfmeta_name_mapping[file_name_st_pdf][0]))
                        file_name_to_pdfmeta_name_mapping[file_name_st_pdf][1] = 1  # was paired

            if not pairing_found:
                print('WARNING: Corresponding pdfmeta pairing not found for maintaince item {}'.format(file_name))

    print('*** Files with keywords extracted, which were NOT matched to any CSV item:')
    for item in file_name_to_keywords_name_mapping:
        if file_name_to_keywords_name_mapping[item][1] == 0:  # not paired
            print('  {}'.format(file_name_to_keywords_name_mapping[item][0]))

    # display all record which were not paired
    print('\n\nRecords with missing pairing of frontpage:')
    num_frontpage_missing = 0
    for item in all_cert_items.keys():
        this_item = all_cert_items[item]
        if 'frontpage_scan' not in this_item.keys():
            print('WARNING: {} no frontpage scan detected'.format(item))
            num_frontpage_missing += 1

    print('\n\nRecords with missing pairing of keywords:')
    num_keywords_missing = 0
    for item in all_cert_items.keys():
        this_item = all_cert_items[item]
        if 'keywords_scan' not in this_item.keys():
            print('WARNING: {} no keywords scan detected'.format(item))
            num_keywords_missing += 1

    print('\n\nRecords with missing pairing of pdfmeta:')
    num_pdfmeta_missing = 0
    for item in all_cert_items.keys():
        this_item = all_cert_items[item]
        if 'pdfmeta_scan' not in this_item.keys():
            print('WARNING: {} no pdfmeta scan detected'.format(item))
            num_pdfmeta_missing += 1

    print('Records without frontpage: {}\nRecords without keywords: {}\nRecords without pdfmeta: {}'.format(
        num_frontpage_missing, num_keywords_missing, num_pdfmeta_missing))

    return all_cert_items


def load_json_files(files_list):
    loaded_jsons = []
    for file_name in files_list:
        with open(file_name) as json_file:
            loaded_jsons.append(json.load(json_file))
    return tuple(loaded_jsons)


def process_pps(download_PPs=False):
    print('*******************************')
    print('Running PP processing module')
    print('*******************************\n')

    extract_pps = False

    current_dir = Path()
    #current_dir = Path('c:\\Certs\\certs_pp_20201008_test\\results')
    #current_dir = Path('c:\\Certs\\certs_pp_20201008\\results')
    results_folder = current_dir / '../results'

    # ensure existence of results folder
    results_folder.mkdir(exist_ok=True)

    # change current directory to store results into results file
    os.chdir(results_folder)

    cc_html_files_dir = current_dir / '../pp_web/'
    cc_html_files_dir.mkdir(exist_ok=True)

    #pp_dir = current_dir / '../latest/cc_pp_20200227/cc_pp/active/pp/test'
    pp_dir = current_dir / '../active_pps'

    # pp_fragments_dir = 'c:\\Certs\\cc_certs_20191208\\cc_pp_txt_fragments\\'
    pp_fragments_dir = current_dir / '../cc_pp_txt_fragments'

    if download_PPs:
        script_path = generate_basic_download_script()
        subprocess.run([str(script_path)], shell=True, check=True)

    if extract_pps:
        all_pp_csv = extract_protectionprofiles_csv(cc_html_files_dir, download_PPs)
        all_pp_front = extract_protectionprofiles_frontpage(pp_dir)
        all_pp_keywords = extract_certificates_keywords(pp_dir, pp_fragments_dir, 'pp')
    else:
        all_pp_csv, all_pp_front, all_pp_keywords = load_json_files(
            ['pp_data_csv_all.json', 'pp_data_frontpage_all.json', 'pp_data_keywords_all.json'])

    all_pp_items = collate_certificates_data({}, all_pp_csv, all_pp_front, all_pp_keywords, {}, 'link_pp_document')
    with open("pp_data_complete.json", "w") as write_file:
        write_file.write(json.dumps(all_pp_items, indent=4, sort_keys=True))

    return all_pp_items


def process_pp_to_id(pp_items, pp_reference_matching, manual_csvpp_to_ppid_mapping):
    '''
    Join information obtained from protection profiles analysis with the metadata already collected
    :param pp_items:
    :param pp_reference_matching:
    :param manual_csvpp_to_ppid_mapping:
    :return:
    '''
    result = pp_items
    for file_name in pp_items.keys():
        file_name_pdf = file_name[:file_name.rfind('__')]
        file_name_no_ext = file_name[:file_name_pdf.rfind('.')]
        # insert info from pp_reference_matching to corresponding pp record
        if is_in_dict(pp_reference_matching, [file_name_no_ext]):
            result[file_name]['pp_analysis'] = pp_reference_matching[file_name_no_ext]
        # insert info from manual_csvpp_to_ppid_mapping to corresponding pp record
        # NOTE: more tha one protection profile can be in single file
        matching_profiles = []
        found_csvids = []
        for csvid in manual_csvpp_to_ppid_mapping.keys():
            if manual_csvpp_to_ppid_mapping[csvid]['pp_filename'] == file_name_no_ext:
                matching_profiles.append(manual_csvpp_to_ppid_mapping[csvid])
                found_csvids.append(csvid)
        if not is_in_dict(result, [file_name, 'pp_analysis']):
            result[file_name]['pp_analysis'] = {}
        result[file_name]['pp_analysis']['separate_profiles'] = matching_profiles

        result[file_name]['processed']['cc_pp_csvid'] = found_csvids


    return result


if __name__ == "__main__":

    if '-h' in sys.argv or '--help' in sys.argv:
        print('Usage: python3 {} [-h | --help] [--download-pps]'.format(sys.argv[0]))
        print('Options:\n'
              '\t-h or --help\tdisplay help\n'
              '\t--download-pps\twill also download active PPs based on active PPs CSV')
        exit(0)

    download_pps = False

    if '--download-pps' in sys.argv:
        download_pps = True

    process_pps(download_pps)
