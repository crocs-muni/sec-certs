import re
import os, sys
import operator
from graphviz import Digraph
from graphviz import Graph
import json
from cert_rules import rules
from time import gmtime, strftime
from shutil import copyfile


REGEXEC_SEP = '[ ,;\]”)(]'
LINE_SEPARATOR = ' '
#LINE_SEPARATOR = ''  # if newline is not replaced with space, long string included in matches are found
TAG_MATCH_COUNTER = 'count'
TAG_MATCH_MATCHES = 'matches'


def search_files(folder):
    for root, dirs, files in os.walk(folder):
        yield from [os.path.join(root, x) for x in files]


def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)


unicode_decode_error = []


def get_line_number(lines, line_length_compensation, match_start_index):
    line_chars_offset = 0
    line_number = 1
    for line in lines:
        line_chars_offset += len(line) + line_length_compensation
        if line_chars_offset > match_start_index:
            # we found the line
            return line_number
        line_number += 1
    # not found
    return -1


def load_cert_file(file_name, limit_max_lines=-1, line_separator=LINE_SEPARATOR):
    lines = []
    was_unicode_decode_error = False
    with open(file_name, 'r') as f:
        try:
            lines = f.readlines()
        except UnicodeDecodeError:
            f.close()
            was_unicode_decode_error = True
            print('UnicodeDecodeError')
            unicode_decode_error.append(file_name)

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

    return whole_text, whole_text_with_newlines


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
    match = match.rstrip(')')
    match = match.rstrip('(')
    match = match.rstrip(',')
    match = match.replace('  ', ' ')  # two spaces into one

    return match


def parse_cert_file(file_name, search_rules, limit_max_lines=-1, line_separator=LINE_SEPARATOR):
    whole_text, whole_text_with_newlines = load_cert_file(file_name, limit_max_lines, line_separator)

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
                    items_found[rule][match][TAG_MATCH_MATCHES] = []

                items_found[rule][match][TAG_MATCH_COUNTER] += 1
                match_span = m.span()
                # estimate line in original text file
                # line_number = get_line_number(lines, line_length_compensation, match_span[0])
                # start index, end index, line number
                items_found[rule][match][TAG_MATCH_MATCHES].append([match_span[0], match_span[1], line_number])


    # highlight all found strings from the input text and store the rest
    for rule_group in items_found_all.keys():
        items_found = items_found_all[rule_group]
        for rule in items_found.keys():
            for match in items_found[rule]:
                whole_text_with_newlines = whole_text_with_newlines.replace(match, 'x' * len(match)) # warning - if AES string is removed before AES-128, -128 will be left in text (does it matter?)

    return items_found_all, (whole_text_with_newlines, was_unicode_decode_error)


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


def print_all_results(items_found_all):
    # print results
    for rule_group in items_found_all.keys():
        print(rule_group)
        items_found = items_found_all[rule_group]
        for rule in items_found.keys():
            print('  ' + rule)
            for match in items_found[rule]:
                print('    {}: {}'.format(match, items_found[rule][match]))


def count_num_items_found(items_found_all):
    num_items_found = 0
    for rule_group in items_found_all.keys():
        items_found = items_found_all[rule_group]
        for rule in items_found.keys():
            for match in items_found[rule]:
                num_items_found += 1

    return num_items_found


def print_dot_graph(filter_rules_group, all_items_found, cert_id, walk_dir, out_dot_name, thick_as_occurences):
    # print dot
    dot = Digraph(comment='Certificate ecosystem: {}'.format(filter_rules_group))
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
                            num_occurrences = str(items_found[rule][match][TAG_MATCH_COUNTER] / 3 + 1)
                        else:
                            num_occurrences = '1'
                        label = str(items_found[rule][match][TAG_MATCH_COUNTER]) # label with number of occurrences
                        dot.edge(this_cert_id, match, color='orange', style='solid', label=label, penwidth=num_occurrences)

    # Generate dot graph using GraphViz into pdf
    dot.render(out_dot_name, view=False)
    print('{} pdf rendered'.format(out_dot_name))


def estimate_cert_id(items_found_all, file_name):
    # find certificate ID which is the most common
    num_items_found_certid_group = 0
    max_occurences = 0
    this_cert_id = ''
    items_found = items_found_all['rules_cert_id']
    for rule in items_found.keys():
        for match in items_found[rule]:
            num_occurences = items_found[rule][match][TAG_MATCH_COUNTER]
            if num_occurences > max_occurences:
                max_occurences = num_occurences
                this_cert_id = match
            num_items_found_certid_group += num_occurences
    print('  -> most frequent cert id: {}'.format(this_cert_id))

    # try to search for certificate id directly in file name - if found, higher priority
    file_name_no_suff = file_name[:file_name.rfind('.')]
    file_name_no_suff = file_name_no_suff[file_name_no_suff.rfind('\\') + 1:]
    for rule in rules['rules_cert_id']:
        file_name_no_suff += ' '
        matches = re.findall(rule, file_name_no_suff)
        if len(matches) > 0:
            # we found cert id directly in name
            print('  -> cert id found directly in certificate name: {}'.format(matches[0]))
            this_cert_id = matches[0]

    return this_cert_id, num_items_found_certid_group


def save_modified_cert_file(target_file, modified_cert_file_text, is_unicode_text):
    write_file = None
    if is_unicode_text:
        write_file = open(target_file, "w", encoding="utf8")
    else:
        write_file = open(target_file, "w")

    try:
        write_file.write(modified_cert_file_text)
    except UnicodeEncodeError as e:
        print(erro_my)
        write_file.close()
        print('UnicodeDecodeError while writing file fragments back')

    write_file.close()


def search_only_headers_bsi(walk_dir):
    LINE_SEPARATOR_STRICT = ' '
    NUM_LINES_TO_INVESTIGATE = 15
    rules_certificate_preface = [
#        '(BSI-DSZ-CC-.+) (?:for|For|zu) (.+) (?:from|der)',
        '(BSI-DSZ-CC-.+) (?:for|For) (.+) from (.*)',
        '(BSI-DSZ-CC-.+) zu (.+) der (.*)',
    ]

    all_vendors = []
    items_found_all = {}
    for file_name in search_files(walk_dir):
        if not os.path.isfile(file_name):
            continue
        print('*** {} ***'.format(file_name))

        whole_text, whole_text_with_newlines = load_cert_file(file_name, NUM_LINES_TO_INVESTIGATE, LINE_SEPARATOR_STRICT)

        items_found_all[file_name] = {}
        items_found = items_found_all[file_name]
        for rule in rules_certificate_preface:
            rule_and_sep = rule + REGEXEC_SEP

            for m in re.finditer(rule_and_sep, whole_text):
                # insert rule if at least one match for it was found
                if rule not in items_found:
                    items_found[rule] = {}

                match_groups = m.groups()
                cert_id = match_groups[0]
                certified_item = match_groups[1]
                vendor = match_groups[2]

                items_found[rule]['cert_id'] = normalize_match_string(cert_id)

                FROM_KEYWORD_LIST = [' from ', ' der ']
                for from_keyword in FROM_KEYWORD_LIST:
                    from_keyword_len = len(from_keyword)
                    if certified_item.find(from_keyword) != -1:
                        print('string **{}** detected in certified item - shall not be here, fixing...'.format(from_keyword))
                        certified_item_first = certified_item[:certified_item.find(from_keyword)]
                        vendor = certified_item[certified_item.find(from_keyword) + from_keyword_len:]
                        certified_item = certified_item_first
                        continue

                items_found[rule]['certified_item'] = normalize_match_string(certified_item)

                end_pos = vendor.find('\f-')
                if end_pos == -1:
                    end_pos = vendor.find('\fBSI')
                if end_pos == -1:
                    end_pos = vendor.find('Bundesamt')
                if end_pos != -1:
                    vendor = vendor[:end_pos]

                vendor = normalize_match_string(vendor)
                items_found[rule]['vendor'] = normalize_match_string(vendor)

                if vendor not in all_vendors:
                    all_vendors.append(vendor)

    print('\n*** Detected vendors:')
    sorted_vendors = sorted(all_vendors)
    for vendor in sorted_vendors:
        print(vendor)

    # store results into file with fixed name and also with time appendix
    with open("certificate_data_bsiheader.json", "w") as write_file:
        write_file.write(json.dumps(items_found_all, indent=4, sort_keys=True))

    print('\n*** Certificates without detected preface:')
    for file_name in items_found_all.keys():
        if len(items_found_all[file_name]) < 1:
            print('No hits for {}'.format(file_name))

    print('\n**********************************')

def search_only_headers_anssi(walk_dir):
    LINE_SEPARATOR_STRICT = ' '
    NUM_LINES_TO_INVESTIGATE = -1
    rules_certificate_preface = [
        'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.*)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables',
        'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.*)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables',
        'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.*)Conformité à un profil de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeurs(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables',
        'Référence du rapport de certification(.+)Nom du produit(.+)()Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeur(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables',
        'Référence du rapport de certification(.+)Nom des produits(.+)Référence/version des produits(.+)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeur\(s\)(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables',
        'Référence du rapport de certification(.+)Nom des produits(.+)Référence/version des produits(.+)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeur(.+)Centre d\'évaluation(.+)Accords de reconnaissance',
        'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité aux profils de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeur\(s\)(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables',
        'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité à un profil de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeur\(s\)(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables',
        'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité à un profil de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeur(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables',
        'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité à des profils de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeurs(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables',
        'Référence du rapport de certification(.+)Nom et version du produit(.+)revision(.+)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeur(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables', # missing version, added via version keyworkd
        'Référence du rapport de certification(.+)Nom et version du produit(.+)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables', # missing version
        'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables',
        'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité aux profils de protection(.+)Critères d\’évaluation et version(.+)Niveau d\’évaluation(.+)Développeurs(.+)Centre d\’évaluation(.+)Accords de reconnaissance applicables',
        'Référence du rapport de certification(.+)Nom du produit \(référence/version\)(.+)Nom de la TOE \(référence/version\)(.+)Conformité à un profil de protection(.+)Critères d\’évaluation et version(.+)Niveau d\’évaluation(.+)Développeurs(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables',
        'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeurs(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables',
        'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur\(s\)(.+)dâ€™Ã©valuation(.+)Accords de reconnaissance applicables',
        'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables',
        'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© Ã  des profils de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeurs(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables',
        'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit \(rÃ©fÃ©rence/version\)(.+)Nom de la TOE \(rÃ©fÃ©rence/version\)(.+)ConformitÃ© Ã  un profil de protection(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeurs(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables',
        'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© aux profisl de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeurs(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance',
        'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© Ã  un profil de protection(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur(.+)Centres dâ€™Ã©valuation(.+)Accords de reconnaissance applicables',
        'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)Version du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables',
        'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© aux profils de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur\(s\)(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables',
        'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)Versions du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables',
        'Certification Report(.+)Nom du produit(.+)Référence/version du produit(.*)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables',
        'Certification report reference(.+)Product name(.+)Product reference(.+)Protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developer(.+)Evaluation facility(.+)Recognition arrangements',
        'Certification report reference(.+)Product name(.+)Product reference(.+)Protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developer(.+)Evaluation facility(.+)Mutual Recognition Agreements',
        'Certification report reference(.+)Product name(.+)Product reference(.+)Protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developers(.+)Evaluation facility(.+)Recognition arrangements',
        'Certification report reference(.+)Product name(.+)Product reference(.+)Protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developer\(s\)(.+)Evaluation facility(.+)Recognition arrangements',
        'Certification report reference(.+)Products names(.+)Products references(.+)protection profile conformity(.+)Evaluation level(.+)Developers(.+)Evaluation facility(.+)Recognition arrangements',
        'Certification report reference(.+)Product name \(reference / version\)(.+)TOE name \(reference / version\)(.+)Protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developers(.+)Evaluation facility(.+)Recognition arrangements',
        'Certification report reference(.+)TOE name(.+)Product\'s reference/ version(.+)TOE\'s reference/ version(.+)Conformité à un profil de protection(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developer(.+)Evaluation facility(.+)Recognition arrangements',
    ]

    rules_certificate_preface = [
        'dddd',
#        'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité aux profil de protection(.+)Critères d\’évaluation et version(.+)Niveau d\’évaluation(.+)Développeur\(s\)(.+)Centre d\’évaluation(.+)Accords de reconnaissance applicables',

    ]

    # 'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)Versions du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables',

    # 'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© aux profils de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur(s)(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables',




    # 'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité aux profil de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeur\(s\)(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables',

    #'Référence du rapport de certification(.+)Nom du produit \(référence/version\)(.+)Nom de la TOE \(référence/version\)(.+)Conformité à un profil de protection(.+)Critères d\’évaluation et version(.+)Niveau d\’évaluation(.+)Développeurs(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables',

    #'Certification report reference(.+)Product name(.+)Product reference(.+)Protection profile conformity(.+)Evaluation level(.+)Developers(.+)Evaluation facility(.+)Recognition arrangements',
    # 'Certification report reference(.+)Product name(.+)Product reference(.+)Protection profile conformity(.+)Evaluation level(.+)Developers(.+)Evaluation facility(.+)Recognition arrangements',

    # 'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité aux profils de protection(.+)Critères d\’évaluation et version(.+)Niveau d\’évaluation(.+)Développeurs(.+)Centre d\’évaluation(.+)Accords de reconnaissance applicables',
    # 'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© Ã  un profil de protection(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur(.+)Centres dâ€™Ã©valuation(.+)Accords de reconnaissance applicables',

    # 'Référence du rapport de certification(.+)Nom et version du produit(.+)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables',

    # 'Certification report reference(.+)Product name(.+)Product reference(.+)Protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developer(.+)Evaluation facility(.+)Mutual Recognition Agreements',

    # Certification Report 2005/41
    # ST19WP18E microcontroller
    # Developer: STMicroelectronics
    #
    # Common Criteria version 2.2
    # EAL5 Augmented
    # (ALC_DVS.2, AVA_MSU.3, AVA_VLA.4)
    # conformant to both PP/9806 and BSI-PP-002-2001 protection profiles
    # Evaluation sponsor: STMicroelectronics Evaluation facility: Serma Technologies

    all_vendors = []
    items_found_all = {}
    for file_name in search_files(walk_dir):
        if not os.path.isfile(file_name):
            continue
        print('*** {} ***'.format(file_name))

        whole_text, whole_text_with_newlines = load_cert_file(file_name)

        items_found_all[file_name] = {}
        items_found = items_found_all[file_name]
        for rule in rules_certificate_preface:
            rule_and_sep = rule + REGEXEC_SEP

            for m in re.finditer(rule_and_sep, whole_text):
                # insert rule if at least one match for it was found
                if rule not in items_found:
                    items_found[rule] = {}

                match_groups = m.groups()
                cert_id = match_groups[0]
                items_found[rule]['cert_id'] = normalize_match_string(cert_id)
                certified_item = match_groups[1]
                items_found[rule]['certified_item'] = normalize_match_string(certified_item)
                certified_item_version = match_groups[2]
                items_found[rule]['certified_item_version'] = normalize_match_string(certified_item_version)
                ref_protection_profiles = match_groups[3]
                items_found[rule]['referenced_protection_profile'] = normalize_match_string(ref_protection_profiles)
                cc_version = match_groups[4]
                items_found[rule]['cc_version'] = normalize_match_string(cc_version)
                cc_security_level = match_groups[5]
                items_found[rule]['cc_security_level'] = normalize_match_string(cc_security_level)
                vendor = match_groups[6]
                vendor = normalize_match_string(vendor)
                items_found[rule]['vendor'] = normalize_match_string(vendor)

                if vendor not in all_vendors:
                    all_vendors.append(vendor)

    print('\n*** Detected vendors:')
    sorted_vendors = sorted(all_vendors)
    for vendor in sorted_vendors:
        print(vendor)

    # store results into file with fixed name and also with time appendix
    with open("certificate_data_anssiheader.json", "w") as write_file:
        write_file.write(json.dumps(items_found_all, indent=4, sort_keys=True))

    print('\n*** Certificates without detected preface:')
    no_hits_count = 0
    for file_name in items_found_all.keys():
        if len(items_found_all[file_name]) < 1:
            print('No hits for {}'.format(file_name))
            no_hits_count += 1

    print('Total no hits files: {}'.format(no_hits_count))
    print('\n**********************************')


MIN_ITEMS_FOUND = 29725


def main():
    # change current directory to store results into results file
    current_dir = os.getcwd()
    os.chdir(current_dir + '\\..\\results\\')

    #walk_dir = 'c:\\Certs\\certs\\cc_search\\only_ic_sc\\test\\'
    #walk_dir = 'c:\\Certs\\certs\\cc_search\\only_ic_sc\\txt\\'
    #walk_dir = 'c:\\Certs\\certs\\cc_search\\20191109_icsconly_current\\'
    #walk_dir = 'c:\\Certs\\certs\\cc_search\\20191109_icsconly_currentandachived\\'
    #walk_dir = 'c:\\Certs\\certs\\cc_search\\20191109_icsconly_currentandachived_bsionly\\'
    walk_dir = 'c:\\Certs\\certs\\cc_search\\20191109_icsconly_currentandachived_anssionly\\'
    #walk_dir = 'c:\\Certs\\certs\\cc_search\\20191109_icsconly_currentandachived_others\\'
    #walk_dir = 'c:\\Certs\\certs\\cc_search\\test\\'
    #walk_dir = 'c:\\Certs\\certs\\cc_search\\test2\\'
    #walk_dir = 'c:\\Certs\\certs\\cc_search\\test3\\'
    #walk_dir = 'c:\\Certs\\certs\\cc_search\\test4\\'
    #walk_dir = 'c:\\Certs\\certs\\cc_search\\test5\\'
    walk_dir = 'c:\\Certs\\certs\\cc_search\\test6\\'

    search_only_headers_anssi(walk_dir)

    #search_only_headers_bsi(walk_dir)


    return

    all_items_found = {}
    cert_id = {}
    all_certid_found_count = {}
    for file_name in search_files(walk_dir):
        if not os.path.isfile(file_name):
            continue

        print('*** {} ***'.format(file_name))

        # parse certificate, return all matches
        all_items_found[file_name], modified_cert_file = parse_cert_file(file_name, rules, -1)

        # try to establish the certificate id of the current certificate
        cert_id[file_name], all_certid_found_count[file_name] = estimate_cert_id(all_items_found[file_name], file_name)

        # save report text with highlighted/replaced matches into \\fragments\\ directory
        base_path = file_name[:file_name.rfind('\\')]
        file_name_short = file_name[file_name.rfind('\\') + 1:]
        target_file = '{}\\..\\fragments\\{}'.format(base_path, file_name_short)
        save_modified_cert_file(target_file, modified_cert_file[0], modified_cert_file[1])

    # store results into file with fixed name and also with time appendix
    with open("certificate_data.json", "w") as write_file:
        write_file.write(json.dumps(all_items_found, indent=4, sort_keys=True))

    # curr_time = strftime("%Y-%m-%d %H:%M:%S", gmtime())
    # curr_time = curr_time.replace(':', '-')
    # curr_time = curr_time.replace(' ', '_')
    # with open("certificate_data_{}.json".format(curr_time), "w") as write_file:
    #     json.dump(all_items_found, write_file)

    print('\nTotal matches found in separate files:')
    #print_total_matches_in_files(all_items_found_count)

    print('\nTotal matches for certificate id found in separate files:')
    print_total_found_cert_ids(all_certid_found_count)

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

    sorted_all_matches = sorted(all_matches)
    for match in sorted_all_matches:
        print(match)

    # verify total matches found
    print('\nTotal matches found: {}'.format(total_items_found))
    if MIN_ITEMS_FOUND > total_items_found:
        print('ERROR: less items found!')
        print(error_less_matches_detected)


if __name__ == "__main__":
    main()