import csv
import json
import re
import secrets
import sys
from pathlib import Path

from pp_statistics import read_json_results, PP_COMPLETE_RESULT

ROOT_DIR = Path('..')
INIT_RESULT_DIR = ROOT_DIR / 'results_init'
RESULT_DIR = ROOT_DIR / 'results'

RESULT_JSON = INIT_RESULT_DIR / 'pp_generated_ids_all.json'

categories = {
    'Access Control Devices and Systems': 'AC',
    'Detection Devices and Systems': 'DD',
    'Biometric Systems and Devices': 'BS',
    'Boundary Protection Devices and Systems': 'BP',
    'Data Protection': 'DP',
    'Databases': 'DB',
    'ICs, Smart Cards and Smart Card-Related Devices and Systems': 'SC',
    'Key Management Systems': 'KM',
    'Mobility': 'MO',
    'Multi-Function Devices': 'MF',
    'Network and Network-Related Devices and Systems': 'ND',
    'Operating Systems': 'OS',
    'Other Devices and Systems': 'OD',
    'Products for Digital Signatures': 'DS',
    'Trusted Computing': 'TC'
}

# PP_NEW
def read_mapper_csv():
    lines = []
    with open(INIT_RESULT_DIR / 'pp_reference_to_id_mapping.csv') as f:
        reader = csv.DictReader(f, delimiter=',')
        for line in reader:
            if line['pp_filename'] != '?':
                lines.append(line)

    return lines

# PP_NEW
def read_pp_mapper():
    results = {}
    with open(RESULT_DIR / 'new_mapping_PP_ref_to_PP_ID.csv') as f:
        reader = csv.DictReader(f, delimiter=',')
        for line in reader:
            if line['pp_filename'] != '?':
                results[line['pp_id_csv']] = line

    return results

# PP_NEW
def generate_id(group, date, version):
    date_parsed = date.replace('/', '')

    counter = str(secrets.randbelow(1000)).zfill(3)

    if 'IEEE' in version:
        version_number = '1.0'

    elif len(version) == 1 and version.isdigit():
        version_number = version + '.0'

    elif re.compile('.*V\d+$').match(version) is not None:
        tmp = re.match('.*V(\d+$)', version).group(1)
        version_number = tmp[0] + '.' + tmp[1]

    else:
        version_txt_to_dec = {'a': '1', 'b': '2', 'c': '3', 'd': '4', 'e': '5', 'f': '6'}

        for k in version_txt_to_dec:
            version = version.replace(k, version_txt_to_dec[k])

        version_number = [m.group(0) for m in re.finditer(r'(\d+\.\d+(?:\.\d+)?)', version)][-1]

    version_string = ''.join([str(int(v)).zfill(2) for v in version_number.split('.')])

    version_string += '00' if len(version_string) == 4 else ''

    return 'PP_{}_{}_V_{}/{}'.format(group, date_parsed, version_string, counter)

# PP_NEW
def generate_ids_legacy(pp_json):
    ids = {}

    print('*** Generating new database of PP IDs ***')

    for pp_file in pp_json:
        pp_file_stem = Path(pp_file).stem

        if pp_file_stem in ids:
            print('SKIPPING: Stem of filename {} already in'.format(pp_file))
            continue

        tmp = pp_json[pp_file]['csv_scan']
        pp_id = generate_id(categories[tmp['cc_category']], tmp['cc_certification_date'], tmp['cc_pp_version'])
        ids[pp_file_stem] = pp_id

    with(open(RESULT_JSON, 'w')) as f:
        f.write(json.dumps(ids, indent=4, sort_keys=True))

    print('\n\n')
    return ids

# PP_NEW
def update_all_ids(all_ids, pp_json):

    print('*** Adding new IDs to the generated ID databse ***')
    for pp_file in pp_json:
        pp_file_stem = Path(pp_file).stem

        if pp_file_stem not in all_ids:
            tmp = pp_json[pp_file]['csv_scan']
            pp_id = generate_id(categories[tmp['cc_category']], tmp['cc_certification_date'], tmp['cc_pp_version'])
            all_ids[pp_file_stem] = pp_id
            print('Creating new ID={} for PP filename {}'.format(pp_id, pp_file_stem))

    with(open(RESULT_JSON, 'w')) as f:
        f.write(json.dumps(all_ids, indent=4, sort_keys=True))

    print('\n\n')

    return all_ids

# PP_NEW
def create_new_mapping(id_list, mapping):
    lines_to_write = []

    print('*** Creating new mapping PP reference to PP ID CSV ***')

    header = 'pp_id_csv,pp_id_legacy,pp_filename,pp_id'
    lines_to_write.append(header)
    print(header)

    for line in mapping:
        pp_filename = line['pp_filename']

        if pp_filename in id_list:
            pp_id = id_list[pp_filename]

            new_line = "{},{},{},{}".format(line['pp_id_csv'], line['pp_id_legacy'], line['pp_filename'], pp_id)
            lines_to_write.append(new_line)
            print(new_line)

    print('\n\n')

    with open(RESULT_DIR / 'new_mapping_PP_ref_to_PP_ID.csv', 'w') as f:
        f.writelines("%s\n" % line for line in lines_to_write)

    return lines_to_write

# PP_NEW
def run_generator(force_legacy_generation=False):
    print('\n\n*******************************')
    print('Running PP ID generator module')
    print('*******************************\n')

    pp_json = read_json_results(PP_COMPLETE_RESULT)
    mapping = read_mapper_csv()

    if not RESULT_JSON.exists() or force_legacy_generation:
        all_ids = generate_ids_legacy(pp_json)
    else:
        all_ids = read_json_results(RESULT_JSON)
        all_ids = update_all_ids(all_ids, pp_json)

    return create_new_mapping(all_ids, mapping)


if __name__ == "__main__":

    if '-h' in sys.argv or '--help' in sys.argv:

        print('Usage: python3 {} [-h | --help] [-f]'.format(sys.argv[0]))
        print('\nOptions:\n'
              '\t-h or --help\tdisplay help\n'
              '\t-f\twill generate new database of IDs and override current database')
        exit(0)

    force = False

    if '-f' in sys.argv:
        force = True

    run_generator(force)
