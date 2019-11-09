import re
import os, sys
import operator
from graphviz import Digraph
from graphviz import Graph

REGEXEC_SEP = '[ ,;\]”)(]'
LINE_SEPARATOR = ' '

rules_vendor = [
    'NXP',
    'Infineon',
    'Samsung',
    '(?:STMicroelectronics|STM)',
    'Feitian',
    'Gemalto',
    'Gemplus',
    'Axalto',
    '(?:Oberthur|OBERTHUR)',
    'Idemia',
    '(?:G\&D|G\+D|Giesecke+Devrient|Giesecke \& Devrient)',
    'Philips',
    'Sagem',
    ]

rules_eval_facilities = [
    'Serma Technologies',
    'THALES - CEACI'
    ]

rules_cert_id = [
    'BSI-DSZ-CC-[0-9]+?-[0-9]+?', # German BSI
    'BSI-DSZ-CC-[0-9]+?-(?:V|v)[0-9]+-[0-9]+?', # German BSI
    'BSI-DSZ-CC-[0-9]+?-(?:V|v)[0-9]+?', # German BSI
    #'CC-Zert-.+?',
    'ANSSI(?:-|-CC-)[0-9]+?/[0-9]+?', # French
    #'ANSSI-CC-CER-F-.+?', # French
    'DCSSI-[0-9]+?/[0-9]+?', # French
    'Certification Report [0-9]+?/[0-9]+?', # French
    'Rapport de certification [0-9]+?/[0-9]+?', # French
    'NSCIB-CC-[0-9][0-9][0-9][0-9].+?', # Netherlands
    'SERTIT-[0-9]+?', # Norway
    'CCEVS-VR-(?:|VID)[0-9]+?-[0-9]+?', # US NSA
    #'[0-9][0-9\-]+?-CR', # Canada
    'CRP[0-9][0-9][0-9][0-9]*?',    # UK CESG
    'CERTIFICATION REPORT No. P[0-9]+?',  # UK CESG
    '20[0-9][0-9]-[0-9]+-INF-[0-9]+?', # Spain
    'KECS-CR-[0-9]+?-[0-9]+?', # Korea
    'KECS-ISIS-[0-9]+?-[0-9][0-9][0-9][0-9]', # Korea
    'CRP-C[0-9]+?-[0-9]+?', # Japan
    'ISCB-[0-9]+?-RPT-[0-9]+?', # Malaysia
    'OCSI/CERT/.+?', # Italia
    '[0-9\.]+?/TSE-CCCS-[0-9]+?', # Turkis CCCS
    'BTBD-.+?', # Turkis CCCS
    ]



rules_protection_profiles = [
    'BSI-PP[-]*.+?',
    'PP-SSCD.+?',
    'Protection Profile',
    'CCMB-20.+?',
    'BSI-CCPP-.+?',
    'ANSSI-CC-PP.+?',
    ]


rules_device_id = [
    'G87-.+?',
    ]

rules_standard_id = [
    'FIPS180-4',
    'FIPS197',
    'PKCS#[1-9]+',
    'TLSv1.1',
    'TLSv1.2',
    'BSI-AIS[ ]*[0-9]+?',
    'AIS[ ]*[0-9]+?',
    'RFC[ ]*[0-9]+?',
    'ISO/IEC 14443',
    ]

rules_security_level = [
    'EAL[ ]*[0-9+]+?',
    'EAL[ ]*[0-9] augmented+?',
    'ITSEC[ ]*E[1-9]*.+?',
    ]

rules_javacard = [
    #'(?:Java Card|JavaCard)',
    #'(?:Global Platform|GlobalPlatform)',
    '(?:Java Card|JavaCard)(?: [2-3]\.[0-9]\.[0-9]|)',
    '(?:Global Platform|GlobalPlatform)(?: [2-3]\.[0-9]\.[0-9]|)',
    ]

rules_crypto_algs = [
    'RSA[- ]*(?:512|768|1024|1280|1536|2048|3072|4096|8192)',
    'RSASSAPKCS1-V1_5',
    'SHA[-]*(?:160|224|256|384|512)',
    'AES[-]*(?:128|192|256|)',
    'SHA-1',
    'MD5',
    'HMAC',
    'Diffie-Hellman',
    'ECDSA',
    'DES',
    'ECC',
    'DTRNG',
    'TRNG',
    'RNG',
    ]

rules_ecc_curves = [
    'P-(?:192|224|256|384|521)',
    'brainpool.+?',
    'secp.+?1',
]

rules_cplc = [
    'IC[ ]*Fabricator',
    'IC[ ]*Type',
    'IC[ ]*Version',
    ]

rules_crypto_engines = [
    'TORNADO',
    'SmartMX',
    ]


rules_crypto_libs = [
    '(?:NesLib|NESLIB) [v]*[0-9.]+',
    'AT1 Secure .{1,30}? Library [v]*[0-9.]+',
    'AT1 Secure RSA/ECC/SHA library',
    'Crypto Library [v]*[0-9.]+',
    'ATMEL Toolbox [0-9.]+',
    ]



rules_defenses = [
    'SPA',
    'DPA',
    '[Ff]+ault induction',
    'ROCA',
    ]




rules_other = [
    'library',
    ]

rules = {}
rules['rules_vendor'] = rules_vendor
rules['rules_cert_id'] = rules_cert_id
rules['rules_protection_profiles'] = rules_protection_profiles
rules['rules_device_id'] = rules_device_id
rules['rules_standard_id'] = rules_standard_id
rules['rules_security_level'] = rules_security_level
rules['rules_javacard'] = rules_javacard
rules['rules_crypto_algs'] = rules_crypto_algs
rules['rules_ecc_curves'] = rules_ecc_curves
rules['rules_cplc'] = rules_cplc
rules['rules_crypto_engines'] = rules_crypto_engines
rules['rules_crypto_libs'] = rules_crypto_libs

rules['rules_defenses'] = rules_defenses



rules['rules_other'] = rules_other


def search_files(folder):
    for root, dirs, files in os.walk(folder):
        yield from [os.path.join(root, x) for x in files]


def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)

unicode_decode_error = []
def parse_cert_file(file_name):
    print('*** {} ***'.format(file_name))

    lines = []

#    with open(file_name, encoding="utf8") as f:
    with open(file_name, 'r') as f:
        try:
            lines = f.readlines()
        except UnicodeDecodeError as e:
            f.close()
            print('UnicodeDecodeError')
            unicode_decode_error.append(file_name)

            with open(file_name, encoding="utf8") as f2:
                # coding failure, try line by line
                line = ' '
                while line:
                    try:
                        line = f2.readline()
                        lines.append(line)
                    except UnicodeDecodeError as e:
                        # ignore error
                        continue


    whole_text = ''
    for line in lines:
        line = line.replace('\n', '')
        whole_text += line
        whole_text += LINE_SEPARATOR

    # apply all rules
    items_found_all = {}
    for rule_group in rules.keys():
        if rule_group not in items_found_all:
            items_found_all[rule_group] = {}

        items_found = items_found_all[rule_group]

        for rule in rules[rule_group]:
            rule_and_sep = rule + REGEXEC_SEP
            matches = re.findall(rule_and_sep, whole_text)

            if len(matches) > 0:
                #print(matches)
                if rule not in items_found:
                    items_found[rule] = {}

                for match in matches:
                    # normalize match
                    match = match.strip()
                    match = match.rstrip(']')
                    match = match.rstrip('/')
                    match = match.rstrip(';')
                    match = match.rstrip('.')
                    match = match.rstrip('”')
                    match = match.rstrip('"')
                    match = match.rstrip(':')
                    match = match.rstrip(')')
                    match = match.rstrip('(')
                    match = match.replace(',', '')
                    if match not in items_found[rule]:
                        items_found[rule][match] = 0

                    items_found[rule][match] += 1

    # find certificate ID which is the most common
    num_items_found_certid_group = 0
    max_occurences = 0
    this_cert_id = ''
    items_found = items_found_all['rules_cert_id']
    for rule in items_found.keys():
        for match in items_found[rule]:
            num_occurences = items_found[rule][match]
            if num_occurences > max_occurences:
                max_occurences = num_occurences
                this_cert_id = match
            num_items_found_certid_group += num_occurences

    # try to search for certificate id directly in file name - if found, higher priority
    for rule in rules['rules_cert_id']:
        matches = re.findall(rule, file_name)
        if len(matches) > 0:
            # we found cert id directly in name
            print('Certificate id found in filename')
            this_cert_id = matches[0]

    # print
    num_items_found = 0
    for rule_group in items_found_all.keys():
        print(rule_group)
        items_found = items_found_all[rule_group]
        for rule in items_found.keys():
            print('  ' + rule)
            for match in items_found[rule]:
                print('    {}: {}'.format(match, items_found[rule][match]))
                num_items_found += 1

    return items_found_all, num_items_found, this_cert_id, num_items_found_certid_group


def print_total_matches_in_files(all_items_found_count):
    sorted_all_items_found_count = sorted(all_items_found_count.items(), key=operator.itemgetter(1))
    for file_name_count in sorted_all_items_found_count:
        print('{:03d}: {}'.format(file_name_count[1], file_name_count[0]))


def print_total_found_cert_ids(all_items_found_certid_count):
    sorted_certid_count = sorted(all_items_found_certid_count.items(), key=operator.itemgetter(1), reverse=True)
    for file_name_count in sorted_certid_count:
        print('{:03d}: {}'.format(file_name_count[1], file_name_count[0]))


def print_guessed_cert_id(cert_id):
    sorted_cert_id = sorted(cert_id.items(), key=operator.itemgetter(1))
    for double in sorted_cert_id:
        just_file_name = double[0]
        if just_file_name.rfind('\\') != -1:
            just_file_name = just_file_name[just_file_name.rfind('\\') + 1:]
        print('{:30s}: {}'.format(double[1], just_file_name))


def print_dot_graph(filter_rules_group, all_items_found, cert_id, walk_dir, out_dot_name, thick_as_occurences):
    # print dot
    dot = Digraph(comment='Certificate ecosystem')
    dot.attr('graph', label='{}'.format(walk_dir), labelloc='t', fontsize='30')
    dot.attr('node', style='filled')

    # insert nodes believed to be cert id for the processed certificates
    for cert in cert_id.keys():
        dot.attr('node', color='green')
        dot.node(cert_id[cert])

    dot.attr('node', color='gray')
    for file_name in all_items_found.keys():
        just_file_name = file_name
        this_cert_id = cert_id[file_name]
        if file_name.rfind('\\') != -1:
            just_file_name = file_name[file_name.rfind('\\') + 1:]

        # insert file name and identified probable certification id
        dot.edge(this_cert_id, this_cert_id, label=just_file_name)

        items_found_group = all_items_found[file_name]
        for rules_group in items_found_group.keys():

            # process only specified rule groups
            if rules_group not in filter_rules_group:
                continue

            items_found = items_found_group[rules_group]
            for rule in items_found.keys():
                for match in items_found[rule]:
                    if match != this_cert_id:
                        if thick_as_occurences:
                            num_occurrences = str(items_found[rule][match] / 3 + 1)
                        else:
                            num_occurrences = '1'
                        label = str(items_found[rule][match]) # label with number of occurrences
                        dot.edge(this_cert_id, match, color='orange', style='solid', label=label, penwidth=num_occurrences)

    # Generate dot graph using GraphViz into pdf
    dot.render(out_dot_name, view=False)


MIN_ITEMS_FOUND = 15010


def main():
    all_items_found = {}

    all_items_found_count = {}
    cert_id = {}
    all_items_found_certid_count = {}
    #walk_dir = 'c:\\Certs\\certs\\cc_search\\only_ic_sc\\test\\'
    #walk_dir = 'c:\\Certs\\certs\\cc_search\\only_ic_sc\\txt\\'
    #walk_dir = 'c:\\Certs\\certs\\cc_search\\20191109_icsconly_current\\'
    walk_dir = 'c:\\Certs\\certs\\cc_search\\20191109_icsconly_currentandachived\\'
    #walk_dir = 'c:\\Certs\\certs\\cc_search\\20191109_icsconly_currentandachived_bsionly\\'
    #walk_dir = 'c:\\Certs\\certs\\cc_search\\20191109_icsconly_currentandachived_anssionly\\'
    #walk_dir = 'c:\\Certs\\certs\\cc_search\\test\\'
    #walk_dir = 'c:\\Certs\\certs\\cc_search\\test2\\'

    total_items_found = 0
    for file_name in search_files(walk_dir):
        if not os.path.isfile(file_name):
            continue

        all_items_found[file_name], all_items_found_count[file_name], cert_id[file_name], all_items_found_certid_count[file_name] = parse_cert_file(file_name)
        total_items_found += all_items_found_count[file_name]

    print('\nTotal matches found in separate files:')
    #print_total_matches_in_files(all_items_found_count)

    print('\nTotal matches for certificate id found in separate files:')
    print_total_found_cert_ids(all_items_found_certid_count)

    print('\nFile name and estimated certificate ID:')
    #print_guessed_cert_id(cert_id)

    print_dot_graph(['rules_cert_id'], all_items_found, cert_id, walk_dir, 'certid_graph.dot', True)
    print_dot_graph(['rules_javacard'], all_items_found, cert_id, walk_dir, 'cert_javacard_graph.dot', False)
    print_dot_graph(['rules_security_level'], all_items_found, cert_id, walk_dir, 'cert_security_level_graph.dot', True)

    # verify total matches found
    print('\nTotal matches found: {}'.format(total_items_found))
    if MIN_ITEMS_FOUND > total_items_found:
        print('ERROR: less items found!')
        print(error_less_matches_detected)


    # for file_name in unicode_decode_error:
    #     print(file_name)

    print("\033[44;33mHello World!\033[m")

if __name__ == "__main__":
    main()