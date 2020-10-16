import csv
import json
import os
import re
import string
import subprocess
import sys
from pathlib import Path
from urllib import parse

from Levenshtein import distance

from pp_process import search_files, load_cert_file, REGEXEC_SEP
from pp_tags_constants import *

ROOT_DIR = Path('..')
RESULT_DIR = ROOT_DIR / 'results'
PP_WEB_DIR = ROOT_DIR / 'pp_web'
INIT_RESULT_DIR = ROOT_DIR / 'results_init'
PP_COMPLETE_RESULT = RESULT_DIR / 'pp_data_complete.json'
PP_FRONTPAGE_RESULT = RESULT_DIR / 'pp_data_frontpage_all.json'

# PP_NEW
# simple object representing line in product_CSV
class CsvItem:
    def __init__(self, pp_refs_string, date):
        self.pp_refs = pp_refs_string.split(',')
        self.date = date

    def extend_refs(self, ids_string):
        self.pp_refs = list(set(self.pp_refs) | set((ids_string.split(','))))


# tags in product_CSV
TAG_CC_CSV_PP_REF = 'Protection Profile(s)'
TAG_CC_CSV_DATE = 'Certification Date'
TAG_CC_CSV_REPORT_URL = 'Certification Report URL'
TAG_CC_CSV_ST = 'Security Target URL'


# PP_UPDATE refactor to load_json_files
# read json file
def read_json_results(path):
    result_json = Path(path)

    with open(result_json, 'r') as f:
        data = json.load(f)

    return data

# PP_NEW
def pp_read_mapping():
    """
    read mapping between PP reference and PP filename
    :return: dictionary where keys are PP references and values are coresponding PP file names
    """
    mapping = {}
    with open(INIT_RESULT_DIR / 'pp_reference_to_id_mapping.csv') as f:
        reader = csv.DictReader(f, delimiter=',')
        for line in reader:
            mapping[line['pp_id_csv']] = line['pp_filename']

    return mapping

# PP_UPDATE - this function is simplified extract_certificates_metadata_csv(), refactor
def read_active_product_csv():
    """
    Read active CC product CSV
    :return: list of CSV lines
    """
    csv_lines = []
    csv_update_pps_json = read_json_results(INIT_RESULT_DIR / 'cc_product_csv_update_mapping.json')

    print('*** Reading active products CSV ***')

    with open(PP_WEB_DIR / 'cc_products_active.csv', encoding='cp1250') as csv_file:
        reader = csv.DictReader(csv_file, delimiter=',')
        header = reader.fieldnames
        expected_columns = len(header)
        counter = 0

        for row in reader:
            counter += 1
            if len(row) != expected_columns:
                print(
                    'WARNING: Incorrect number of columns in row {} (likely separator , in item name), going to fix...'
                        .format(len(csv_lines) + 2))

                if len(row) == expected_columns + 1:
                    row[header[1]] = row[header[1]] + row[header[2]]
                    for i in range(3, expected_columns):
                        row[header[i - 1]] = row[header[i]]
                    row[header[expected_columns - 1]] = row[None][0]
                    del row[None]

            # check for update of 'Protection Profile' column based on update
            security_target = Path(row[TAG_CC_CSV_ST]).stem
            if security_target in csv_update_pps_json:
                row[TAG_CC_CSV_PP_REF] = csv_update_pps_json[security_target]

            csv_lines.append(row)

    print('\n\n')
    return csv_lines

# PP_NEW
# build dictionary of CSVItem objects conformant to a PP based on the product_CSV
def pp_get_csv_dict():
    result = {}
    cc_csv_data = read_active_product_csv()

    for line in cc_csv_data:
        if line[TAG_CC_CSV_PP_REF] is None or line[TAG_CC_CSV_PP_REF] == '':
            continue

        file_name = Path(line[TAG_CC_CSV_REPORT_URL].split("/")[-1]).stem
        if file_name in result:
            result[file_name].extend_refs(line[TAG_CC_CSV_PP_REF])
        else:
            result[file_name] = CsvItem(line[TAG_CC_CSV_PP_REF], line[TAG_CC_CSV_DATE])

    return result


def generate_download_script():
    csv_cc_data = read_active_product_csv()

    script_path = RESULT_DIR / 'download_cc_report_active.bat'

    url_common = 'https://www.commoncriteriaportal.org/files/epfiles/'

    with open(script_path, "w") as f:
        f.write('cd ..\n')
        f.write('mkdir cc_report_active\n')
        f.write('cd cc_report_active\n')
        for line in csv_cc_data:
            file_name = line[TAG_CC_CSV_REPORT_URL].split("/")[-1]
            f.write('curl \"{}\" -o \"{}\"\n'.format(url_common + parse.quote(file_name), file_name))
            f.write('pdftotext -raw \"{}\"\n\n'.format(file_name))

    os.chmod(script_path, int('755', base=8))

    return script_path


# appends values from one dict to the second dict
def append_dict(result, to_append):
    for k, v in to_append.items():
        if k in result:
            result[k] = list(set(result[k]) | set(v))
        else:
            result[k] = v
    return result


# from dict of CSVItems build a set of PP IDs that are referenced from product_CSV
def get_pp_references(cc_data):
    cc_ids_set = set()

    for csv_item in cc_data.values():
        cc_ids_set.update(csv_item.pp_refs)

    return cc_ids_set


# first scan - similarity of ID gathered by frontpage_scan and PP references in product_CSV
def id_and_reference_similarity(pp_data, cc_data):
    pp_header_ids = []
    pp_filenames_stem = []
    bsi_ids_to_filenames = {}

    for k in pp_data.keys():
        path = Path(k)
        pp_filenames_stem.append(path.stem)

    for pp in pp_data:
        for header in pp_data[pp]:
            if TAG_PP_ID in header:
                pp_id = header[TAG_PP_ID]
                pp_header_ids.append(pp_id)
                bsi_ids_to_filenames[pp_id] = Path(pp).stem

    cc_ids_set = get_pp_references(cc_data)
    cc_ids_list = list(cc_ids_set)

    result_anssi = extract_anssi(pp_filenames_stem, cc_ids_list)
    result_bsi_ids = extract_bsi(pp_header_ids, cc_ids_list)

    # convert bsi ids to filenames
    result_bsi = {}
    for k, v in result_bsi_ids.items():
        for candidate in list(v):
            if k not in result_bsi:
                result_bsi[k] = []
            result_bsi[k].append(bsi_ids_to_filenames[candidate])

    return append_dict(result_anssi, result_bsi)


# first part of first scan concerned on BSI IDs
def extract_bsi(pp_ids, cc_references):
    bsi_rule1 = re.compile(r'^BSI.+(\d{3}).(\d{4})\S*')
    bsi_rule2 = re.compile(r'^BSI\D+(\d{4})$')
    bsi_rule3 = re.compile(r'^BSI\D+(\d{4}).V(\d)\S*')

    filtering1 = lambda x: list(filter(None.__ne__, map(bsi_rule1.search, x)))
    filtering2 = lambda x: list(filter(None.__ne__, map(bsi_rule2.search, x)))
    filtering3 = lambda x: list(filter(None.__ne__, map(bsi_rule3.search, x)))

    pp_matches = filtering1(pp_ids)
    pp_matches += filtering2(pp_ids)
    pp_matches += filtering3(pp_ids)

    cc_matches = filtering1(cc_references)
    cc_matches += filtering2(cc_references)
    cc_matches += filtering3(cc_references)

    result = validate_candidates(pp_matches, cc_matches)

    print("\n*** Summary\nTotal PP IDs: {}".format(len(pp_ids)))
    print("Total unique PP references: {}".format(len(cc_references)))
    print("Total BSI references: {}".format(len(cc_matches)))
    print("References with candidates: {}".format(len(result)))
    print("Possible PP to be mapped: {}\n\n".format(len(pp_matches)))

    return result


# the second part of first algorithm focused on ANSSI IDs
def extract_anssi(pp_filenames, cc_references):
    anssi_rule = re.compile(r'^ANSSI.+(\d{4}).(\d{2}).*', flags=re.IGNORECASE)

    filtering = lambda x: list(filter(None.__ne__, map(anssi_rule.search, x)))

    pp_matches = filtering(pp_filenames)
    cc_matches = filtering(cc_references)

    result = validate_candidates(pp_matches, cc_matches)

    print("\n*** Summary\nTotal active PPs: {}".format(len(pp_filenames)))
    print("Total unique PP references: {}".format(len(cc_references)))
    print("Total ANSSI references: {}".format(len(cc_matches)))
    print("References with candidates: {}".format(len(result)))
    print("Possible PP to be mapped: {}\n\n".format(len(pp_matches)))

    return result


# helper for first page scan that compares matching groups and determines the candidates
def validate_candidates(pp_matches, cc_matches):
    pp_matches_names = set(match.group(0) for match in pp_matches)
    result = {}

    print('*** CSV based finding of PP id similarity with a PP referrence ***')
    for cc in cc_matches:
        possibilities = []
        for pp in pp_matches:
            pp_groups_num = len(pp.groups())
            cc_groups_num = len(cc.groups())
            if pp_groups_num == cc_groups_num:
                same = True
                for i in range(1, pp_groups_num + 1):
                    if pp.group(i) != cc.group(i):
                        same = False
                        break
                if same:
                    possibilities.append(pp.group(0))

        print('Reference {} have candidate(s) {}'.format(cc.group(0), possibilities))
        possible_set = set(possibilities)
        pp_matches_names -= possible_set

        if len(possible_set) > 0:
            result[cc.group(0)] = list(possible_set)

        if len(possible_set) == 1:
            print("High probability of matched ID.")

    #print("Not matched PP ids: {}\n".format(pp_matches_names))
    return result


# the second scan based on the PP filename and PP reference in product_CSV similarity
def find_reference_to_filename(pp_data, cc_data):
    result = {}
    hits = 0
    pp_refs = get_pp_references(cc_data)

    print('*** CSV based searching of PP referrence similarity with a PP filenames ***')

    for pp_ref in pp_refs:
        tmp = []
        for pp in pp_data:
            a = pp_ref.lower()
            b = Path(pp).stem
            if distance(a, b.lower()) <= 1:
                tmp.append(b)

        if len(tmp) > 0:
            result[pp_ref] = tmp
            print('Reference {} have candidate(s) {}'.format(pp_ref, result[pp_ref]))
            hits += 1

    print("\n*** Summary")
    print('Unique PP references: {}'.format(len(pp_refs)))
    print('Different Protection Profiles: {}'.format(len(pp_data)))
    print('References with candidates: {}'.format(hits))
    print('\n\n')

    return result


# searches the PP reference inside the certification report, CSV based
def find_refeference_in_text_csv_based(csv_data, pp_data):
    rules = [r'([pP]rotection [pP]rofile.?)', r'([pP]{2}.?)']
    total_in_dir = 0
    total_with_ref = 0
    match = 0
    result_with_frequencies = {}
    result = {}
    no_hit_reports = []
    pp_title_dic = {}
    pp_year_dic = {}

    print('*** CSV based search of PP references inside a ST certification report ***')

    for pp in pp_data:
        pp_title_dic[pp] = ' '.join(re.sub('[' + string.punctuation + ']', '', pp_data[pp]['csv_scan']['cc_pp_name'])
                                    .split())
        pp_year_dic[pp] = pp_data[pp]['csv_scan']['cc_certification_date'].split('/')[-1]

    for file_name in search_files(ROOT_DIR / 'cc_report_active'):
        file_ext = file_name[file_name.rfind('.'):]
        if file_ext != '.txt':
            continue
        if not os.path.isfile(file_name):
            continue
        total_in_dir += 1
        found = set()
        file_name_stem = Path(file_name).stem

        if file_name_stem not in csv_data:
            continue

        cc_references = csv_data[file_name_stem].pp_refs

        whole_text, whole_text_with_newlines, was_unicode_decode_error = load_cert_file(file_name)

        for rule in rules:

            for m in re.finditer(rule + REGEXEC_SEP, whole_text):

                end_index = m.start(1)
                orig_string = whole_text[end_index: end_index + 1000]
                parsed = ' '.join(re.sub('[' + string.punctuation + ']', '', orig_string).split())

                for title in pp_title_dic:
                    if pp_title_dic[title].lower() in parsed.lower() and pp_year_dic[title] in parsed:
                        found.add(Path(title).stem)

        if len(found):
            match += 1

            for pp_id in cc_references:

                if pp_id not in result_with_frequencies:
                    result_with_frequencies[pp_id] = {}
                    result[pp_id] = []

                for candidate in found:
                    if candidate not in result_with_frequencies[pp_id]:
                        result_with_frequencies[pp_id][candidate] = 1
                        result[pp_id].append(candidate)
                    else:
                        result_with_frequencies[pp_id][candidate] += 1

            print('{} with reference(s) {} possibly conformant to PP(s) with stemmed filename(s) {}'
                  .format(file_name, csv_data[file_name_stem].pp_refs, found))

        else:
            no_hit_reports.append(file_name)
        total_with_ref += 1

    print('\n\n')

    for r in result_with_frequencies:
        s = sorted(result_with_frequencies[r].items(), key=lambda x: x[1], reverse=True)
        print('Reference {} have candidate PP(s) with filename(s) {}'.format(r, s))

    print('\n\n*** ST that claim conformance to a PP by product_CSV with no hit ***')
    for f in no_hit_reports:
        print(f)

    print('\nSummary:')
    print('Certificates: {}'.format(total_in_dir))
    print('Certificates using PP: {}'.format(total_with_ref))
    print('Certificates using PP with hit: {}'.format(match))
    print('References with candidate ID: {}'.format(len(result_with_frequencies)))
    print('\n\n')

    return result_with_frequencies, result


# TODO prepisat nazov
# third scan searching PP information inside a product's certificaiton report, now searching PP usage not mentioned in product_CSV
def find_refeference_in_text_non_CSV(csv_data, pp_data):

    print('*** Starting non-CSV based matching by searching PP reference within PP body ***')

    rules = [r'([pP]rotection [pP]rofile.?)', r'([pP]{2}.?)']

    rules_not = [r'[nN]ot.{0,20}[cC]onform.{0,20}(?:[pP]{2}|[pP]rotection [pP]rofile)',
                 r'[cC]onform.{0,15}profil.{0,15}protect.{0,15}(?:Néant|Aucun)',
                 r'[nN]ot.{0,10}base.{0,20}[pP]rotection [pP]rofile',
                 r'[cC]onform.{0,20}[Nn]one']

    total_in_dir = 0
    total_with_no_ref = 0
    result = {}
    no_hit_reports = []

    pp_title_dic = {}
    pp_year_dic = {}

    with open(INIT_RESULT_DIR / 'found_pp_reference_text_hit_files.txt', 'r') as f:
        hit_files_stemmed = [curr_pos.rstrip() for curr_pos in f.readlines()]

    for pp in pp_data:
        pp_title_dic[pp] = ' '.join(re.sub('[' + string.punctuation + ']', ' ', pp_data[pp]['csv_scan']['cc_pp_name'])
                                    .split())
        pp_year_dic[pp] = pp_data[pp]['csv_scan']['cc_certification_date'].split('/')[-1]

    #TODO prepisat zlozku
    for file_name in search_files(ROOT_DIR / 'cc_report_active'):

        file_ext = file_name[file_name.rfind('.'):]
        if file_ext != '.txt':
            continue

        if not os.path.isfile(file_name):
            continue

        total_in_dir += 1
        found = set()
        file_name_stem = Path(file_name).stem

        if file_name_stem in csv_data or file_name_stem in hit_files_stemmed:
            continue

        whole_text, whole_text_with_newlines, was_unicode_decode_error = load_cert_file(file_name)

        for rule in rules:

            for m in re.finditer(rule + REGEXEC_SEP, whole_text):

                end_index = m.start(1)
                orig_string = whole_text[end_index - 500: end_index + 500]
                parsed = ' '.join(re.sub('[' + string.punctuation + ']', ' ', orig_string).split())

                for pp_file_name in pp_title_dic:

                    if pp_title_dic[pp_file_name].lower() in parsed.lower():
                        contain_not_rule = False
                        for not_rule in rules_not:
                            if re.search(not_rule, whole_text):
                                contain_not_rule = True
                                break
                        if contain_not_rule:
                            continue

                        found.add(Path(pp_file_name).stem)

        if len(found):
            print('{} might be conformant to the following PP filename(s) {}'.format(file_name, found))

            hit_files_stemmed.append(file_name_stem)
            result[file_name_stem] = list(found)

        else:
            no_hit_reports.append(file_name)

        total_with_no_ref += 1

    with open(INIT_RESULT_DIR / 'found_pp_reference_text_hit_files.txt', 'w') as f:
        f.writelines("%s\n" % file for file in hit_files_stemmed)

    print('\nSummary:')
    print('Certificates: {}'.format(total_in_dir))
    print('Certificates not using PP according to the product CSV: {}'.format(total_with_no_ref))
    print('Certificates not using PP according to the product CSV, that might be conformant to some PP: {}'.format(
        len(result)))
    print('\n\n')

    return result


def performMatching(download_st_reports=False):
    print('\n\n*******************************')
    print('Running matcher module')
    print('*******************************\n')

    if download_st_reports:
        execute_path = generate_download_script()
        subprocess.run([str(execute_path)], shell=True, check=True)

    result = {}
    exact_matches = 0
    csv_dict = pp_get_csv_dict()
    referrence_id_mapping = pp_read_mapping()

    pp_complete_data = read_json_results(PP_COMPLETE_RESULT)
    pp_frontpage_data = read_json_results(PP_FRONTPAGE_RESULT)

    candidates = id_and_reference_similarity(pp_frontpage_data, csv_dict)

    tmp_result = find_reference_to_filename(pp_complete_data, csv_dict)
    candidates = append_dict(candidates, tmp_result)

    tmp_result_with_frequencies, tmp_result = find_refeference_in_text_csv_based(csv_dict, pp_complete_data)
    candidates = append_dict(candidates, tmp_result)

    for referrence in candidates:
        result[referrence] = {}
        result[referrence]['candidate_pp_filenames'] = candidates[referrence]
        exact_match = False
        pp_ID = ''

        if referrence not in referrence_id_mapping:
            print('Error: referrence {} not in known real mapping CSV!'.format(referrence))
        else:
            pp_ID = referrence_id_mapping[referrence]

            if referrence_id_mapping[referrence] in candidates[referrence]:
                exact_match = True
                exact_matches += 1

        result[referrence]['exact_match'] = exact_match
        result[referrence]['real_pp_filename'] = pp_ID

    file_to_id_mapping = {}
    for pp_id in result.keys():
        item = result[pp_id]
        item['cc_pp_id'] = pp_id
        file_to_id_mapping[item['real_pp_filename']] = item

    print('**** Summary of CSV based matching ***')
    print('PP Referrences with candidates: {}'.format(len(result)))
    print('PP Referrences, where one of the candidates is PP ID: {}\n\n'.format(exact_matches))

    with open(RESULT_DIR / 'CSV_based_PP_referrence_to_PP_filename.json', 'w') as f:
        f.write(json.dumps(result, indent=4, sort_keys=True))

    # BUGBUG: analyze this matching
    result_non_csv = find_refeference_in_text_non_CSV(csv_dict, pp_complete_data)
    with open(RESULT_DIR / 'Non_CSV_based_PP_referrence_to_PP_filename.json', 'w') as f:
        f.write(json.dumps(result_non_csv, indent=4, sort_keys=True))

    return result, file_to_id_mapping


if __name__ == "__main__":

    if '-h' in sys.argv or '--help' in sys.argv:

        print('Usage: python3 {} [-h | --help] [--download-st-certification-reports]'.format(sys.argv[0]))
        print('\nOptions:\n'
              '\t-h or --help\tdisplay help\n'
              '\t--download-st-certification-reports\twill also download active ST certification reprots based on active '
              'products CSV')
        exit(0)

    download_st_reports = False

    if '--download-st-certification-reports' in sys.argv:
        download_st_reports = True

    performMatching(download_st_reports)
