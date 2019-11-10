import re
import os, sys
import operator
from graphviz import Digraph
from graphviz import Graph
import json
from cert_rules import rules

REGEXEC_SEP = '[ ,;\]”)(]'
LINE_SEPARATOR = ' '


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
    print('Certificate id based on the most frequent: {}'.format(this_cert_id))

    # try to search for certificate id directly in file name - if found, higher priority
    file_name_no_suff = file_name[:file_name.rfind('.')]
    file_name_no_suff = file_name_no_suff[file_name_no_suff.rfind('\\') + 1:]
    for rule in rules['rules_cert_id']:
        file_name_no_suff += ' '
        matches = re.findall(rule, file_name_no_suff)
        if len(matches) > 0:
            # we found cert id directly in name
            print('Certificate id found directly in filename: {}'.format(matches[0]))
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
    print('{} pdf rendered'.format(out_dot_name))

MIN_ITEMS_FOUND = 29577


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
    #walk_dir = 'c:\\Certs\\certs\\cc_search\\test3\\'

    total_items_found = 0
    for file_name in search_files(walk_dir):
        if not os.path.isfile(file_name):
            continue

        all_items_found[file_name], all_items_found_count[file_name], cert_id[file_name], all_items_found_certid_count[file_name] = parse_cert_file(file_name)
        total_items_found += all_items_found_count[file_name]

    with open("certificate_data.json", "w") as write_file:
        json.dump(all_items_found, write_file)

    print('\nTotal matches found in separate files:')
    #print_total_matches_in_files(all_items_found_count)

    print('\nTotal matches for certificate id found in separate files:')
    print_total_found_cert_ids(all_items_found_certid_count)

    print('\nFile name and estimated certificate ID:')
    #print_guessed_cert_id(cert_id)

    print_dot_graph(['rules_cert_id'], all_items_found, cert_id, walk_dir, 'certid_graph.dot', True)
#    print_dot_graph(['rules_javacard'], all_items_found, cert_id, walk_dir, 'cert_javacard_graph.dot', False)
#    print_dot_graph(['rules_security_level'], all_items_found, cert_id, walk_dir, 'cert_security_level_graph.dot', True)
#    print_dot_graph(['rules_crypto_libs'], all_items_found, cert_id, walk_dir, 'cert_crypto_libs_graph.dot', False)
#    print_dot_graph(['rules_vendor'], all_items_found, cert_id, walk_dir, 'rules_vendor.dot', False)
#    print_dot_graph(['rules_crypto_algs'], all_items_found, cert_id, walk_dir, 'rules_crypto_algs.dot', False)
#    print_dot_graph(['rules_protection_profiles'], all_items_found, cert_id, walk_dir, 'rules_protection_profiles.dot', False)
#    print_dot_graph(['rules_defenses'], all_items_found, cert_id, walk_dir, 'rules_defenses.dot', False)


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