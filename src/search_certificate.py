import re
import os, sys
import operator
from graphviz import Digraph
from graphviz import Graph
import json
import csv
from cert_rules import rules
from time import gmtime, strftime
from shutil import copyfile
from enum import Enum
from tabulate import tabulate
import matplotlib.pyplot as plt; plt.rcdefaults()
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.pyplot import figure
from dateutil import parser

# if True, then exception is raised when unexpect intermediate number is obtained
# Used as sanity check during development to detect sudden drop in number of extracted features
STOP_ON_UNEXPECTED_NUMS = False
APPEND_DETAILED_MATCH_MATCHES = False
VERBOSE = False

REGEXEC_SEP = '[ ,;\]”)(]'
LINE_SEPARATOR = ' '
#LINE_SEPARATOR = ''  # if newline is not replaced with space, long string included in matches are found
TAG_MATCH_COUNTER = 'count'
TAG_MATCH_MATCHES = 'matches'

TAG_CERT_HEADER_PROCESSED = 'cert_header_processed'

TAG_CERT_ID = 'cert_id'
TAG_CC_SECURITY_LEVEL = 'cc_security_level'
TAG_CC_VERSION = 'cc_version'
TAG_CERT_LAB = 'cert_lab'
TAG_CERT_ITEM = 'cert_item'
TAG_CERT_ITEM_VERSION = 'cert_item_version'
TAG_DEVELOPER = 'developer'
TAG_REFERENCED_PROTECTION_PROFILES = 'ref_protection_profiles'
TAG_HEADER_MATCH_RULES = 'match_rules'


def search_files(folder):
    for root, dirs, files in os.walk(folder):
        yield from [os.path.join(root, x) for x in files]


def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)


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


def is_in_dict(target_dict, path):
    current_level = target_dict
    for item in path:
        if item not in current_level:
            return False
        else:
            current_level = current_level[item]
    return True


def get_item_from_dict(target_dict, path):
    current_level = target_dict
    for item in path:
        if item not in current_level:
            return None
        else:
            current_level = current_level[item]
    return current_level


def plot_bar_graph(data, x_data_labels, y_label, title, file_name):
    fig_width = round(len(data) / 2)
    if fig_width < 10:
        fig_width = 10
    figure(num=None, figsize=(fig_width, 8), dpi=200, facecolor='w', edgecolor='k')
    y_pos = np.arange(len(x_data_labels))
    plt.bar(y_pos, data, align='center', alpha=0.5)
    plt.xticks(y_pos, x_data_labels)
    plt.xticks(rotation=45)
    plt.ylabel(y_label)
    plt.title(title)
    x1, x2, y1, y2 = plt.axis()
    plt.axis((x1, x2, y1 - 1, y2))
    plt.savefig(file_name + '.png', bbox_inches='tight')
    plt.savefig(file_name + '.pdf', bbox_inches='tight')


def plot_heatmap_graph(data_matrix, x_data_ticks, y_data_ticks, x_label, y_label, title, file_name):
    plt.figure(figsize=(round(len(x_data_ticks) / 2), 8), dpi=200, facecolor='w', edgecolor='k')
    #color_map = 'BuGn'
    color_map = 'Purples'
    plt.imshow(data_matrix, cmap=color_map, interpolation='none', aspect='auto')
    #sns.heatmap(data_matrix, cmap=color_map, linewidth=0.5)
    x_pos = np.arange(len(y_data_ticks))
    plt.yticks(x_pos, y_data_ticks)
    y_pos = np.arange(len(x_data_ticks))
    plt.xticks(y_pos, x_data_ticks)
    plt.xticks(rotation=90, ha='center')
    plt.gca().invert_yaxis()
    x1, x2, y1, y2 = plt.axis()
    plt.axis((x1, x2, y1 - 0.5, y2))
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.title(title)
    plt.savefig(file_name + '.png', bbox_inches='tight')
    plt.savefig(file_name + '.pdf', bbox_inches='tight')


def compute_and_plot_hist(data, bins, y_label, title, file_name):
    hist_refs = np.histogram(data, bins)
    hist_labels = []
    for index in range(0, len(bins) - 1):
        if bins[index] == bins[index + 1] - 1:
            hist_labels.append('{}'.format(bins[index]))
        else:
            hist_labels.append('{}-{}'.format(bins[index], bins[index + 1]))
    # plot bar graph with number of certificates referenced by given number of other certificates
    plot_bar_graph(hist_refs[0], hist_labels, y_label, title, file_name)


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


def load_cert_html_file(file_name):
    with open(file_name, 'r') as f:
        try:
            whole_text = f.read()
        except UnicodeDecodeError:
            f.close()
            with open(file_name, encoding="utf8") as f2:
                whole_text = f2.read()

    return whole_text


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
    whole_text, whole_text_with_newlines, was_unicode_decode_error = load_cert_file(file_name, limit_max_lines, line_separator)

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
                #items_found[rule][match][TAG_MATCH_MATCHES].append([match_span[0], match_span[1], line_number])
                if APPEND_DETAILED_MATCH_MATCHES:
                    items_found[rule][match][TAG_MATCH_MATCHES].append([match_span[0], match_span[1]])

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


def depricated_print_dot_graph_keywordsonly(filter_rules_group, all_items_found, cert_id, walk_dir, out_dot_name, thick_as_occurences):
    # print dot
    dot = Digraph(comment='Certificate ecosystem: {}'.format(filter_rules_group))
    dot.attr('graph', label='{}'.format(walk_dir), labelloc='t', fontsize='30')
    dot.attr('node', style='filled')

    # insert nodes believed to be cert id for the processed certificates
    for cert in cert_id.keys():
        if cert != "":
            dot.attr('node', color='green')
            dot.node(cert_id[cert])

    dot.attr('node', color='gray')
    for file_name in all_items_found.keys():
        just_file_name = file_name
        this_cert_id = cert_id[file_name]

        if file_name.rfind('\\') != -1:
            just_file_name = file_name[file_name.rfind('\\') + 1:]

        # insert file name and identified probable certification id
        if this_cert_id != "":
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
                        if this_cert_id != "":
                            dot.edge(this_cert_id, match, color='orange', style='solid', label=label, penwidth=num_occurrences)

    # Generate dot graph using GraphViz into pdf
    dot.render(out_dot_name, view=False)
    print('{} pdf rendered'.format(out_dot_name))


def print_dot_graph(filter_rules_group, all_items_found, walk_dir, out_dot_name, thick_as_occurences):
    # print dot
    dot = Digraph(comment='Certificate ecosystem: {}'.format(filter_rules_group))
    dot.attr('graph', label='{}'.format(walk_dir), labelloc='t', fontsize='30')
    dot.attr('node', style='filled')

    # insert nodes believed to be cert id for the processed certificates
    for cert_long_id in all_items_found.keys():
        if is_in_dict(all_items_found[cert_long_id], ['processed', 'cert_id']):
            dot.attr('node', color='green')  # URL='https://www.commoncriteriaportal.org/' doesn't work for pdf
            dot.node(all_items_found[cert_long_id]['processed']['cert_id'])

    dot.attr('node', color='gray')
    for cert_long_id in all_items_found.keys():
        # do not continue if no keywords were extracted
        if 'keywords_scan' not in all_items_found[cert_long_id].keys():
            continue

        cert = all_items_found[cert_long_id]
        this_cert_id = ''
        if is_in_dict(cert, ['processed', 'cert_id']):
            this_cert_id = cert['processed']['cert_id']
        if is_in_dict(cert, ['csv_scan', 'cert_item_name']):
            this_cert_name = cert['csv_scan']['cert_item_name']

        just_file_name = cert['csv_scan']['link_cert_report_file_name']

        # insert file name and identified probable certification id
        if this_cert_id != "":
            dot.edge(this_cert_id, this_cert_id, label=just_file_name)

        items_found_group = all_items_found[cert_long_id]['keywords_scan']
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
                        if this_cert_id != "":
                            dot.edge(this_cert_id, match, color='orange', style='solid', label=label, penwidth=num_occurrences)

    # Generate dot graph using GraphViz into pdf
    dot.render(out_dot_name, view=False)
    print('{} pdf rendered'.format(out_dot_name))


def plot_certid_to_item_graph(item_path, all_items_found, walk_dir, out_dot_name, thick_as_occurences):
    # print dot
    dot = Digraph(comment='Certificate ecosystem: {}'.format(item_path))
    dot.attr('graph', label='{}'.format(walk_dir), labelloc='t', fontsize='30')
    dot.attr('node', style='filled')

    # insert nodes believed to be cert id for the processed certificates
    for cert_long_id in all_items_found.keys():
        if is_in_dict(all_items_found[cert_long_id], ['processed', 'cert_id']):
            dot.attr('node', color='green')  # URL='https://www.commoncriteriaportal.org/' doesn't work for pdf
            dot.node(all_items_found[cert_long_id]['processed']['cert_id'])

    dot.attr('node', color='gray')
    for cert_long_id in all_items_found.keys():
        # do not continue if no values with specified path were extracted
        if item_path[0] not in all_items_found[cert_long_id].keys():
            continue

        cert = all_items_found[cert_long_id]
        this_cert_id = ''
        if is_in_dict(cert, ['processed', 'cert_id']):
            this_cert_id = cert['processed']['cert_id']

        if is_in_dict(cert, [item_path[0], item_path[1]]):
            items_found = cert[item_path[0]][item_path[1]]
            for rule in items_found:
                for match in items_found[rule]:
                    if match != this_cert_id:
                        if thick_as_occurences:
                            num_occurrences = str(items_found[rule][match][TAG_MATCH_COUNTER] / 3 + 1)
                        else:
                            num_occurrences = '1'
                        label = str(items_found[rule][match][TAG_MATCH_COUNTER]) # label with number of occurrences
                        if this_cert_id != "":
                            dot.edge(this_cert_id, match, color='orange', style='solid', label=label, penwidth=num_occurrences)

    # Generate dot graph using GraphViz into pdf
    dot.render(out_dot_name, view=False)
    print('{} pdf rendered'.format(out_dot_name))

def analyze_references_graph(filter_rules_group, all_items_found):
    # build cert_id to item name mapping
    certid_info = {}
    for cert_long_id in all_items_found.keys():
        cert = all_items_found[cert_long_id]
        if is_in_dict(cert, ['processed', 'cert_id']):
            if is_in_dict(cert, ['frontpage_scan', 'cert_item']):
                this_cert_id = cert['processed']['cert_id']
                if this_cert_id not in certid_info.keys():
                    certid_info[this_cert_id] = {}
                certid_info[this_cert_id]['cert_item'] = cert['frontpage_scan']['cert_item']

    # build list of references
    referenced_by = {}
    for cert_long_id in all_items_found.keys():
        # do not continue if no keywords were extracted ()
        if 'keywords_scan' not in all_items_found[cert_long_id].keys():
            continue

        cert = all_items_found[cert_long_id]
        this_cert_id = ''
        if is_in_dict(cert, ['processed', 'cert_id']):
            this_cert_id = cert['processed']['cert_id']

        items_found_group = all_items_found[cert_long_id]['keywords_scan']
        for rules_group in items_found_group.keys():

            # process only specified rule groups
            if rules_group not in filter_rules_group:
                continue

            items_found = items_found_group[rules_group]
            for rule in items_found.keys():
                for match in items_found[rule]:
                    if match != this_cert_id:
                        if this_cert_id != "":
                            # add this_cert_id to the list of references of match item
                            if match not in referenced_by:
                                referenced_by[match] = []
                            if this_cert_id not in referenced_by[match]:
                                referenced_by[match].append(this_cert_id)

    #
    # process direct references
    #
    referenced_by_direct_nums = {}
    for cert_id in referenced_by.keys():
        referenced_by_direct_nums[cert_id] = len(referenced_by[cert_id])

    print('### Certificates sorted by number of other certificates directly referencing them:')
    sorted_ref_direct = sorted(referenced_by_direct_nums.items(), key=operator.itemgetter(1), reverse=False)
    direct_refs = []
    for cert_id in sorted_ref_direct:
        direct_refs.append(cert_id[1])
        if is_in_dict(certid_info, [cert_id[0], 'cert_item']):
            print('  {} : {}x directly: {}'.format(cert_id[0], cert_id[1], certid_info[cert_id[0]]['cert_item']))
        else:
            print('  {} : {}x directly'.format(cert_id[0], cert_id[1]))
    print('  Total number of certificates referenced at least once: {}'.format(len(sorted_ref_direct)))

    step = 5
    max_refs = max(direct_refs) + step
    bins = [1, 2, 3, 4, 5] + list(range(6, max_refs + 1, step))
    compute_and_plot_hist(direct_refs, bins, 'Number of certificates', '# certificates with specific number of direct references', 'cert_direct_refs_frequency.png')


    EXPECTED_CERTS_REFERENCED_ONCE = 942
    if EXPECTED_CERTS_REFERENCED_ONCE != len(sorted_ref_direct):
        print('  ERROR: Different than expected num certificates referenced at least once: {} vs. {}'.format(EXPECTED_CERTS_REFERENCED_ONCE, len(sorted_ref_direct)))
        if STOP_ON_UNEXPECTED_NUMS:
            raise ValueError('ERROR: Stopping on unexpected intermediate numbers')

    #
    # compute indirect num of references
    #
    referenced_by_indirect = {}
    for cert_id in referenced_by.keys():
        referenced_by_indirect[cert_id] = set()
        for item in referenced_by[cert_id]:
            referenced_by_indirect[cert_id].add(item)

    new_change_detected = True
    while new_change_detected:
        new_change_detected = False

        certids_list = referenced_by.keys()
        for cert_id in certids_list:
            tmp_referenced_by_indirect_nums = referenced_by_indirect[cert_id].copy()
            for referencing in tmp_referenced_by_indirect_nums:
                if referencing in referenced_by.keys():
                    tmp_referencing = referenced_by_indirect[referencing].copy()
                    for in_referencing in tmp_referencing:
                        if in_referencing not in referenced_by_indirect[cert_id]:
                            new_change_detected = True
                            referenced_by_indirect[cert_id].add(in_referencing)

    print('### Certificates sorted by number of other certificates indirectly referencing them:')
    referenced_by_indirect_nums = {}
    for cert_id in referenced_by_indirect.keys():
        referenced_by_indirect_nums[cert_id] = len(referenced_by_indirect[cert_id])

    sorted_ref_indirect = sorted(referenced_by_indirect_nums.items(), key=operator.itemgetter(1), reverse=False)
    indirect_refs = []
    for cert_id in sorted_ref_indirect:
        indirect_refs.append(cert_id[1])
        if is_in_dict(certid_info, [cert_id[0], 'cert_item']):
            print('  {} : {}x indirectly: {}'.format(cert_id[0], cert_id[1], certid_info[cert_id[0]]['cert_item']))
        else:
            print('  {} : {}x indirectly'.format(cert_id[0], cert_id[1]))

    step = 5
    max_refs = max(indirect_refs) + step
    bins = [1, 2, 3, 4, 5] + list(range(6, max_refs + 1, step))
    compute_and_plot_hist(indirect_refs, bins, 'Number of certificates', '# certificates with specific number of indirect references', 'cert_indirect_refs_frequency.png')


def plot_schemes_multi_line_graph(x_ticks, data, prominent_data, x_label, y_label, title, file_name):

    figure(num=None, figsize=(16, 8), dpi=200, facecolor='w', edgecolor='k')

    line_types = ['-', ':', '-.', '--']
    num_lines_plotted = 0
    data_sorted = sorted(data.keys())
    for group in data_sorted:
        items_in_year = []
        for item in sorted(data[group]):
            num = len(data[group][item])
            items_in_year.append(num)

        if group in prominent_data:
            plt.plot(x_ticks, items_in_year, line_types[num_lines_plotted % len(line_types)], label=group, linewidth=3)
        else:
            # plot minor suppliers dashed
            plt.plot(x_ticks, items_in_year, line_types[num_lines_plotted % len(line_types)], label=group, linewidth=2)

        # change line type to prevent color repetitions
        num_lines_plotted += 1

    plt.rcParams.update({'font.size': 16})
    plt.legend(loc=2)
    plt.xticks(x_ticks, rotation=45)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.title(title)
    plt.savefig(file_name + '.png', bbox_inches='tight')
    plt.savefig(file_name + '.pdf', bbox_inches='tight')


def analyze_cert_years_frequency(all_cert_items):
    scheme_date = {}
    level_date = {}
    manufacturer_date = {}
    manufacturer_items = {}
    START_YEAR = 1997
    END_YEAR = 2020
    for cert_long_id in all_cert_items.keys():
        cert = all_cert_items[cert_long_id]
        if is_in_dict(cert, ['csv_scan', 'cc_certification_date']):
            # extract year of certification
            cert_date = cert['csv_scan']['cc_certification_date']
            parsed_date = parser.parse(cert_date)
            year = parsed_date.year

            # extract EAL level
            if is_in_dict(cert, ['csv_scan', 'cc_security_level']):
                level = cert['csv_scan']['cc_security_level']
                if level.find(',') != -1:
                    level = level[:level.find(',')]  # trim list of augmented items
                level_out = level
                if level == 'None':
                    if cert['csv_scan']['cc_protection_profiles'] != '':
                        level_out = 'Protection Profile'

                if level_out not in level_date.keys():
                    level_date[level_out] = {}
                    for year in range(START_YEAR, END_YEAR):
                        level_date[level_out][year] = []
                level_date[level_out][year].append(cert_long_id)

            # extract scheme
            if is_in_dict(cert, ['csv_scan', 'cc_scheme']):
                cc_scheme = cert['csv_scan']['cc_scheme']
                if cc_scheme not in scheme_date.keys():
                    scheme_date[cc_scheme] = {}
                    for year in range(START_YEAR, END_YEAR):
                        scheme_date[cc_scheme][year] = []
                scheme_date[cc_scheme][year].append(cert_long_id)

            # extract manufacturer(s)
            if 'cc_manufacturer_simple_list' in cert['processed']:
                for manufacturer in cert['processed']['cc_manufacturer_simple_list']:
                    if manufacturer not in manufacturer_date.keys():
                        manufacturer_date[manufacturer] = {}
                        for year in range(START_YEAR, END_YEAR):
                            manufacturer_date[manufacturer][year] = []
                    if manufacturer not in manufacturer_items:
                        manufacturer_items[manufacturer] = 0

                    manufacturer_date[manufacturer][year].append(cert_long_id)
                    manufacturer_items[manufacturer] += 1

    # print manufacturers frequency
    sorted_by_occurence = sorted(manufacturer_items.items(), key=operator.itemgetter(1))
    print('\n### Frequency of certificates per company')
    print('  # companies: {}'.format(len(manufacturer_items)))
    print('  # companies with more than 1 cert: {}'.format(len([i for i in sorted_by_occurence if i[1] > 1])))
    print('  # companies with more than 10 cert: {}'.format(len([i for i in sorted_by_occurence if i[1] > 10])))
    print('  # companies with more than 50 cert: {}\n'.format(len([i for i in sorted_by_occurence if i[1] > 50])))
    for manufacturer in sorted_by_occurence:
        print('  {}: {}x'.format(manufacturer[0], manufacturer[1]))

    # plot graphs showing cert. scheme and EAL in years
    years = np.arange(START_YEAR, END_YEAR)
    plot_schemes_multi_line_graph(years, scheme_date, ['DE', 'JP', 'FR', 'US', 'CA'], 'Year of issuance', 'Number of certificates issued', 'CC certificates issuance frequency per scheme and year', 'num_certs_in_years')
    plot_schemes_multi_line_graph(years, level_date, ['EAL4+', 'EAL5+','EAL2+', 'Protection Profile'], 'Year of issuance', 'Number of certificates issued', 'Certificates issuance frequency per EAL and year', 'num_certs_eal_in_years')

    sc_manufacturers = ['Gemalto', 'NXP Semiconductors', 'Samsung', 'STMicroelectronics', 'Oberthur Technologies',
                        'Infineon Technologies AG', 'G+D Mobile Security GmbH', 'ATMEL Smart Card ICs', 'Idemia',
                        'Athena Smartcard', 'Renesas', 'Philips Semiconductors GmbH', 'Oberthur Card Systems']

    # plot only top manufacturers
    top_manufacturers = dict(sorted_by_occurence[len(sorted_by_occurence) - 20:]).keys()  # top 20 manufacturers
    plot_manufacturers_date = {}
    for manuf in manufacturer_date.keys():
        if manuf in top_manufacturers:
            plot_manufacturers_date[manuf] = manufacturer_date[manuf]
    plot_schemes_multi_line_graph(years, plot_manufacturers_date, sc_manufacturers, 'Year of issuance', 'Number of certificates issued', 'Top 20 manufacturers of certified items per year', 'manufacturer_in_years')

    # plot only smartcard manufacturers
    plot_manufacturers_date = {}
    for manuf in manufacturer_date.keys():
        if manuf in sc_manufacturers:
            plot_manufacturers_date[manuf] = manufacturer_date[manuf]
    plot_schemes_multi_line_graph(years, plot_manufacturers_date, [], 'Year of issuance', 'Number of certificates issued', 'Smartcard-related manufacturers of certified items per year', 'manufacturer_sc_in_years')

def analyze_eal_frequency(all_cert_items):
    scheme_level = {}
    for cert_long_id in all_cert_items.keys():
        cert = all_cert_items[cert_long_id]
        if is_in_dict(cert, ['csv_scan', 'cc_scheme']):
            if is_in_dict(cert, ['csv_scan', 'cc_security_level']):
                cc_scheme = cert['csv_scan']['cc_scheme']
                level = cert['csv_scan']['cc_security_level']
                if level.find(',') != -1:
                    level = level[:level.find(',')]  # trim list of augmented items
                if cc_scheme not in scheme_level.keys():
                    scheme_level[cc_scheme] = {}
                if level not in scheme_level[cc_scheme]:
                    scheme_level[cc_scheme][level] = 0
                scheme_level[cc_scheme][level] += 1

    print('\n### CC EAL levels based on the certification scheme:')
    for cc_scheme in sorted(scheme_level.keys()):
        print(cc_scheme)
        for level in sorted(scheme_level[cc_scheme].keys()):
            print('  {:5}: {}x'.format(level, scheme_level[cc_scheme][level]))

    print('\n')
    eal_headers = ['EAL1', 'EAL1+','EAL2', 'EAL2+','EAL3', 'EAL3+','EAL4', 'EAL4+','EAL5',
                 'EAL5+','EAL6', 'EAL6+','EAL7', 'EAL7+', 'None']

    total_eals = {}
    for level in eal_headers:
        total_eals[level] = 0

    cc_eal_freq = []
    sum_total = 0
    for cc_scheme in sorted(scheme_level.keys()):
        this_scheme_levels = [cc_scheme]
        total = 0
        for level in eal_headers:
            if level in scheme_level[cc_scheme]:
                this_scheme_levels.append(scheme_level[cc_scheme][level])
                total += scheme_level[cc_scheme][level]
                total_eals[level] += scheme_level[cc_scheme][level]
            else:
                this_scheme_levels.append(0)

        this_scheme_levels.append(total)
        sum_total += total
        cc_eal_freq.append(this_scheme_levels)

    total_eals_row = []
    for level in sorted(total_eals.keys()):
        total_eals_row.append(total_eals[level])

    # plot bar graph with frequency of CC EAL levels
    plot_bar_graph(total_eals_row, eal_headers, 'Number of certificates', 'Number of certificates of specific EAL level', 'cert_eal_frequency')

    # Print table with results over national schemes
    total_eals_row.append(sum_total)
    cc_eal_freq.append(['Total'] + total_eals_row)
    print(tabulate(cc_eal_freq, ['CC scheme'] + eal_headers + ['Total']))


def analyze_sars_frequency(all_cert_items):
    sars_freq = {}
    for cert_long_id in all_cert_items.keys():
        cert = all_cert_items[cert_long_id]
        if is_in_dict(cert, ['keywords_scan', 'rules_security_target_class']):
            sars = cert['keywords_scan']['rules_security_target_class']
            for sar_rule in sars:
                for sar_hit in sars[sar_rule]:
                    if sar_hit not in sars_freq.keys():
                        sars_freq[sar_hit] = 0
                    sars_freq[sar_hit] += 1


    print('\n### CC security assurance components frequency:')
    sars_labels = sorted(sars_freq.keys())
    sars_freq_nums = []
    for sar in sars_labels:
        print('{:10}: {}x'.format(sar, sars_freq[sar]))
        sars_freq_nums.append(sars_freq[sar])

    print('\n### CC security assurance components frequency sorted by num occurences:')
    sorted_by_occurence = sorted(sars_freq.items(), key=operator.itemgetter(1))
    for sar in sorted_by_occurence:
        print('{:10}: {}x'.format(sar[0], sar[1]))

    # plot bar graph with frequency of CC SARs
    plot_bar_graph(sars_freq_nums, sars_labels, 'Number of certificates', 'Number of certificates mentioning specific security assurance component (SAR)\nAll listed SARs occured at least once', 'cert_sars_frequency')
    sars_freq_nums, sars_labels = (list(t) for t in zip(*sorted(zip(sars_freq_nums, sars_labels), reverse = True)))
    plot_bar_graph(sars_freq_nums, sars_labels, 'Number of certificates', 'Number of certificates mentioning specific security assurance component (SAR)\nAll listed SARs occured at least once', 'cert_sars_frequency_sorted')

    # plot heatmap of SARs frequencies based on type (row) and level (column)
    sars_labels = sorted(sars_freq.keys())
    sars_unique_names = []
    for sar in sars_labels:
        if sar.find('.') != -1:
            name = sar[:sar.find('.')]
        else:
            name = sar
        if name not in sars_unique_names:
            sars_unique_names.append(name)

    sars_unique_names = sorted(sars_unique_names)
    max_sar_level = 6
    num_sars = len(sars_unique_names)
    sar_heatmap = []
    sar_matrix = []
    for i in range(1, max_sar_level + 1):
        sar_row = []
        for name in sars_unique_names:
            sar_row.append(0)
        sar_matrix.append(sar_row)

    for sar in sorted_by_occurence:
        if sar[0].find('.') != -1:
            name = sar[0][:sar[0].find('.')]
            name_index = sars_unique_names.index(name)
            level = int(sar[0][sar[0].find('.') + 1:])
            sar_matrix[level - 1][name_index] = sar[1]

    # plot heatmap graph with frequency of SAR levels
    y_data_labels = range(1, max_sar_level + 2)
    plot_heatmap_graph(sar_matrix, sars_unique_names, y_data_labels, 'Security assurance component (SAR) class', 'Security assurance components (SAR) level', 'Frequency of achieved levels for Security assurance component (SAR) classes', 'cert_sars_heatmap')


def estimate_cert_id(frontpage_scan, keywords_scan, file_name):
    # check if cert id was extracted from frontpage (most priority)
    frontpage_cert_id = ''
    if frontpage_scan != None:
        if 'cert_id' in frontpage_scan.keys():
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
                #print('  -> cert id found directly in certificate name: {}'.format(matches[0]))
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


def save_modified_cert_file(target_file, modified_cert_file_text, is_unicode_text):
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


def process_raw_header(items_found):
    return items_found


def print_specified_property_sorted(section_name, item_name, items_found_all):
    specific_item_values = []
    for file_name in items_found_all.keys():
        if section_name in items_found_all[file_name].keys():
            if item_name in items_found_all[file_name][section_name].keys():
                specific_item_values.append(items_found_all[file_name][item_name])
            else:
                print('WARNING: Item {} not found in file {}'.format(item_name, file_name))

    print('*** Occurrences of *{}* item'.format(item_name))
    sorted_items = sorted(specific_item_values)
    for item in sorted_items:
        print(item)


def print_found_properties(items_found_all):
    print_specified_property_sorted(TAG_CERT_ID, items_found_all)
    print_specified_property_sorted(TAG_CERT_ITEM , items_found_all)
    print_specified_property_sorted(TAG_CERT_ITEM_VERSION, items_found_all)
    print_specified_property_sorted(TAG_REFERENCED_PROTECTION_PROFILES, items_found_all)
    print_specified_property_sorted(TAG_CC_VERSION , items_found_all)
    print_specified_property_sorted(TAG_CC_SECURITY_LEVEL, items_found_all)
    print_specified_property_sorted(TAG_DEVELOPER , items_found_all)
    print_specified_property_sorted(TAG_CERT_LAB, items_found_all)


def search_only_headers_bsi(walk_dir):
    LINE_SEPARATOR_STRICT = ' '
    NUM_LINES_TO_INVESTIGATE = 15
    rules_certificate_preface = [
        '(BSI-DSZ-CC-.+?) (?:for|For) (.+?) from (.*)',
        '(BSI-DSZ-CC-.+?) zu (.+?) der (.*)',
    ]

    items_found_all = {}
    files_without_match = []
    for file_name in search_files(walk_dir):
        if not os.path.isfile(file_name):
            continue
        file_ext = file_name[file_name.rfind('.'):]
        if file_ext != '.txt':
            continue
        print('*** {} ***'.format(file_name))

        no_match_yet = True
        #
        # Process front page with info: cert_id, certified_item and developer
        #
        whole_text, whole_text_with_newlines, was_unicode_decode_error = load_cert_file(file_name, NUM_LINES_TO_INVESTIGATE, LINE_SEPARATOR_STRICT)

        for rule in rules_certificate_preface:
            rule_and_sep = rule + REGEXEC_SEP

            for m in re.finditer(rule_and_sep, whole_text):
                if no_match_yet:
                    items_found_all[file_name] = {}
                    items_found_all[file_name] = {}
                    items_found = items_found_all[file_name]
                    items_found[TAG_HEADER_MATCH_RULES] = []
                    no_match_yet = False

                # insert rule if at least one match for it was found
                if rule not in items_found[TAG_HEADER_MATCH_RULES]:
                    items_found[TAG_HEADER_MATCH_RULES].append(rule)

                match_groups = m.groups()
                cert_id = match_groups[0]
                certified_item = match_groups[1]
                developer = match_groups[2]

                FROM_KEYWORD_LIST = [' from ', ' der ']
                for from_keyword in FROM_KEYWORD_LIST:
                    from_keyword_len = len(from_keyword)
                    if certified_item.find(from_keyword) != -1:
                        print('string **{}** detected in certified item - shall not be here, fixing...'.format(from_keyword))
                        certified_item_first = certified_item[:certified_item.find(from_keyword)]
                        developer = certified_item[certified_item.find(from_keyword) + from_keyword_len:]
                        certified_item = certified_item_first
                        continue

                end_pos = developer.find('\f-')
                if end_pos == -1:
                    end_pos = developer.find('\fBSI')
                if end_pos == -1:
                    end_pos = developer.find('Bundesamt')
                if end_pos != -1:
                    developer = developer[:end_pos]

                items_found[TAG_CERT_ID] = normalize_match_string(cert_id)
                items_found[TAG_CERT_ITEM] = normalize_match_string(certified_item)
                items_found[TAG_DEVELOPER] = normalize_match_string(developer)
                items_found[TAG_CERT_LAB] = 'BSI'

        #
        # Process page with more detailed certificate info
        # PP Conformance, Functionality, Assurance
        rules_certificate_third = [
            'PP Conformance: (.+)Functionality: (.+)Assurance: (.+)The IT Product identified',
        ]

        whole_text, whole_text_with_newlines, was_unicode_decode_error = load_cert_file(file_name)

        for rule in rules_certificate_third:
            rule_and_sep = rule + REGEXEC_SEP

            for m in re.finditer(rule_and_sep, whole_text):
                # check if previous rules had at least one match
                if not TAG_CERT_ID in items_found.keys():
                    print('ERROR: front page not found for file: {}'.format(file_name))

                match_groups = m.groups()
                ref_protection_profiles = match_groups[0]
                cc_version = match_groups[1]
                cc_security_level = match_groups[2]

                items_found[TAG_REFERENCED_PROTECTION_PROFILES] = normalize_match_string(ref_protection_profiles)
                items_found[TAG_CC_VERSION] = normalize_match_string(cc_version)
                items_found[TAG_CC_SECURITY_LEVEL] = normalize_match_string(cc_security_level)

        if no_match_yet:
            files_without_match.append(file_name)

    if False:
        print_found_properties(items_found_all)

    with open("certificate_data_bsiheader.json", "w") as write_file:
        write_file.write(json.dumps(items_found_all, indent=4, sort_keys=True))

    print('\n*** Certificates without detected preface:')
    for file_name in files_without_match:
        print('No hits for {}'.format(file_name))
    print('Total no hits files: {}'.format(len(files_without_match)))
    print('\n**********************************')

    return items_found_all, files_without_match


def search_only_headers_anssi(walk_dir):
    class HEADER_TYPE(Enum):
        HEADER_FULL = 1
        HEADER_MISSING_CERT_ITEM_VERSION = 2
        HEADER_MISSING_PROTECTION_PROFILES = 3
        HEADER_DUPLICITIES = 4

    rules_certificate_preface = [
        (HEADER_TYPE.HEADER_FULL, 'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.*)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.*)Conformité à un profil de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeurs(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'Référence du rapport de certification(.+)Nom du produit(.+)()Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeur (.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'Référence du rapport de certification(.+)Nom des produits(.+)Référence/version des produits(.+)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeur\(s\)(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'Référence du rapport de certification(.+)Nom des produits(.+)Référence/version des produits(.+)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeur (.+)Centre d\'évaluation(.+)Accords de reconnaissance'),
        (HEADER_TYPE.HEADER_FULL, 'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité aux profils de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeur\(s\)(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité à un profil de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeur\(s\)(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité à un profil de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeur (.+)Centre d’évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité à des profils de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeurs(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité aux profils de protection(.+)Critères d\’évaluation et version(.+)Niveau d\’évaluation(.+)Développeurs(.+)Centre d\’évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'Référence du rapport de certification(.+)Nom du produit \(référence/version\)(.+)Nom de la TOE \(référence/version\)(.+)Conformité à un profil de protection(.+)Critères d\’évaluation et version(.+)Niveau d\’évaluation(.+)Développeurs(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité aux profil de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeur\(s\)(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeur\(s\)(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'Référence du rapport de certification(.+)Nom du produit \(référence/version\)(.+)Nom de la TOE \(référence/version\)(.+)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'Référence du rapport de certification(.+)Nom du produit(.+)Référence du produit(.+)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité aux profils de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),

        (HEADER_TYPE.HEADER_FULL, 'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeurs(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur\(s\)(.+)dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur (.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© Ã  des profils de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeurs(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit \(rÃ©fÃ©rence/version\)(.+)Nom de la TOE \(rÃ©fÃ©rence/version\)(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeurs(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'Certification Report(.+)Nom du produit(.+)Référence/version du produit(.*)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© aux profisl de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeurs(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur (.+)Centres dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)Version du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur (.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© aux profils de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur\(s\)(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)Versions du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur (.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeurs(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_FULL, 'Certification report reference(.+)Product name(.+)Product reference(.+)Protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developer (.+)Evaluation facility(.+)Recognition arrangements'),
        (HEADER_TYPE.HEADER_FULL, 'Certification report reference(.+)Product name(.+)Product reference(.+)Protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developer (.+)Evaluation facility(.+)Mutual Recognition Agreements'),
        (HEADER_TYPE.HEADER_FULL, 'Certification report reference(.+)Product name(.+)Product reference(.+)Protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developers(.+)Evaluation facility(.+)Recognition arrangements'),
        (HEADER_TYPE.HEADER_FULL, 'Certification report reference(.+)Product name(.+)Product reference(.+)Protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developer\(s\)(.+)Evaluation facility(.+)Recognition arrangements'),
        (HEADER_TYPE.HEADER_FULL, 'Certification report reference(.+)Products names(.+)Products references(.+)protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developers(.+)Evaluation facility(.+)Recognition arrangements'),
        (HEADER_TYPE.HEADER_FULL, 'Certification report reference(.+)Product name \(reference / version\)(.+)TOE name \(reference / version\)(.+)Protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developers(.+)Evaluation facility(.+)Recognition arrangements'),
        (HEADER_TYPE.HEADER_FULL, 'Certification report reference(.+)TOE name(.+)Product\'s reference/ version(.+)TOE\'s reference/ version(.+)Conformité à un profil de protection(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developer (.+)Evaluation facility(.+)Recognition arrangements'),

        # corrupted text (duplicities)
        (HEADER_TYPE.HEADER_DUPLICITIES, 'RÃ©fÃ©rencce du rapport de d certification n(.+)Nom du p produit(.+)RÃ©fÃ©rencce/version du produit(.+)ConformiitÃ© Ã  un profil de d protection(.+)CritÃ¨res d dâ€™Ã©valuation ett version(.+)Niveau dâ€™â€™Ã©valuation(.+)DÃ©velopp peurs(.+)Centre dâ€™â€™Ã©valuation(.+)Accords d de reconnaisssance applicab bles'),

        # rules without product version
        (HEADER_TYPE.HEADER_MISSING_CERT_ITEM_VERSION, 'Référence du rapport de certification(.+)Nom et version du produit(.+)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_MISSING_CERT_ITEM_VERSION, 'Référence du rapport de certification(.+)Nom et version du produit(.+)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeur (.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),
        (HEADER_TYPE.HEADER_MISSING_CERT_ITEM_VERSION, 'Référence du rapport de certification(.+)Nom du produit(.+)Conformité à un profil de protection(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),

        # rules without protection profile
        (HEADER_TYPE.HEADER_MISSING_PROTECTION_PROFILES, 'Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Critères d\'évaluation et version(.+)Niveau d\'évaluation(.+)Développeurs(.+)Centre d\'évaluation(.+)Accords de reconnaissance applicables'),
    ]

#    rules_certificate_preface = [
#        (HEADER_TYPE.HEADER_FULL, 'ddddd'),
#    ]

    # statistics about rules success rate
    num_rules_hits = {}
    for rule in rules_certificate_preface:
        num_rules_hits[rule[1]] = 0

    items_found_all = {}
    files_without_match = []
    for file_name in search_files(walk_dir):
        if not os.path.isfile(file_name):
            continue
        file_ext = file_name[file_name.rfind('.'):]
        if file_ext != '.txt':
            continue
        print('*** {} ***'.format(file_name))

        whole_text, whole_text_with_newlines, was_unicode_decode_error = load_cert_file(file_name)

        # for ANSII and DCSSI certificates, front page starts only on third page after 2 newpage signs
        pos = whole_text.find('')
        if pos != -1:
            pos = whole_text.find('', pos)
            if pos != -1:
                whole_text = whole_text[pos:]

        no_match_yet = True
        other_rule_already_match = False
        other_rule = ''
        rule_index = -1
        for rule in rules_certificate_preface:
            rule_index += 1
            rule_and_sep = rule[1] + REGEXEC_SEP

            for m in re.finditer(rule_and_sep, whole_text):
                if no_match_yet:
                    items_found_all[file_name] = {}
                    items_found_all[file_name] = {}
                    items_found = items_found_all[file_name]
                    items_found[TAG_HEADER_MATCH_RULES] = []
                    no_match_yet = False

                # insert rule if at least one match for it was found
                if rule not in items_found[TAG_HEADER_MATCH_RULES]:
                    items_found[TAG_HEADER_MATCH_RULES].append(rule[1])

                if not other_rule_already_match:
                    other_rule_already_match = True
                    other_rule = rule
                else:
                    print('WARNING: multiple rules are matching same certification document: ' + file_name)

                num_rules_hits[rule[1]] += 1  # add hit to this rule

                match_groups = m.groups()

                index_next_item = 0

                items_found[TAG_CERT_ID] = normalize_match_string(match_groups[index_next_item])
                index_next_item += 1

                items_found[TAG_CERT_ITEM] = normalize_match_string(match_groups[index_next_item])
                index_next_item += 1

                if rule[0] == HEADER_TYPE.HEADER_MISSING_CERT_ITEM_VERSION:
                    items_found[TAG_CERT_ITEM_VERSION] = ''
                else:
                    items_found[TAG_CERT_ITEM_VERSION] = normalize_match_string(match_groups[index_next_item])
                    index_next_item += 1

                if rule[0] == HEADER_TYPE.HEADER_MISSING_PROTECTION_PROFILES:
                    items_found[TAG_REFERENCED_PROTECTION_PROFILES] = ''
                else:
                    items_found[TAG_REFERENCED_PROTECTION_PROFILES] = normalize_match_string(match_groups[index_next_item])
                    index_next_item += 1

                items_found[TAG_CC_VERSION] = normalize_match_string(match_groups[index_next_item])
                index_next_item += 1

                items_found[TAG_CC_SECURITY_LEVEL] = normalize_match_string(match_groups[index_next_item])
                index_next_item += 1

                items_found[TAG_DEVELOPER] = normalize_match_string(match_groups[index_next_item])
                index_next_item += 1

                items_found[TAG_CERT_LAB] = normalize_match_string(match_groups[index_next_item])
                index_next_item += 1

        if no_match_yet:
            files_without_match.append(file_name)

    if False:
        print_found_properties(items_found_all)

    # store results into file with fixed name and also with time appendix
    with open("certificate_data_anssiheader.json", "w") as write_file:
        write_file.write(json.dumps(items_found_all, indent=4, sort_keys=True))

    print('\n*** Certificates without detected preface:')
    for file_name in files_without_match:
        print('No hits for {}'.format(file_name))
    print('Total no hits files: {}'.format(len(files_without_match)))
    print('\n**********************************')

    if True:
        print('# hits for rule')
        sorted_rules = sorted(num_rules_hits.items(), key=operator.itemgetter(1), reverse=True)
        used_rules = []
        for rule in sorted_rules:
            print('{:4d} : {}'.format(rule[1], rule[0]))
            if rule[1] > 0:
                used_rules.append(rule[0])

    return items_found_all, files_without_match


def extract_certificates_frontpage(walk_dir):
    anssi_items_found, anssi_files_without_match = search_only_headers_anssi(walk_dir)
    bsi_items_found, bsi_files_without_match = search_only_headers_bsi(walk_dir)

    print('*** Files without detected header')
    files_without_match = list(set(anssi_files_without_match) & set(bsi_files_without_match))
    for file_name in files_without_match:
        print(file_name)
    print('Total no hits files: {}'.format(len(files_without_match)))

    items_found_all = {**anssi_items_found, **bsi_items_found}
    # store results into file with fixed name and also with time appendix
    with open("certificate_data_frontpage_all.json", "w") as write_file:
        write_file.write(json.dumps(items_found_all, indent=4, sort_keys=True))

    return items_found_all


def extract_certificates_keywords(walk_dir, fragments_dir, file_prefix):
    all_items_found = {}
    cert_id = {}
    for file_name in search_files(walk_dir):
        if not os.path.isfile(file_name):
            continue
        file_ext = file_name[file_name.rfind('.'):]
        if file_ext != '.txt':
            continue

        print('*** {} ***'.format(file_name))

        # parse certificate, return all matches
        all_items_found[file_name], modified_cert_file = parse_cert_file(file_name, rules, -1)

        # try to establish the certificate id of the current certificate
        cert_id[file_name] = estimate_cert_id(None, all_items_found[file_name], file_name)

        # save report text with highlighted/replaced matches into \\fragments\\ directory
        base_path = file_name[:file_name.rfind('\\')]
        file_name_short = file_name[file_name.rfind('\\') + 1:]
        target_file = '{}\\{}'.format(fragments_dir, file_name_short)
        save_modified_cert_file(target_file, modified_cert_file[0], modified_cert_file[1])

    # store results into file with fixed name and also with time appendix
    with open("{}_data_keywords_all.json".format(file_prefix), "w") as write_file:
        write_file.write(json.dumps(all_items_found, indent=4, sort_keys=True))

    print('\nTotal matches found in separate files:')
    # print_total_matches_in_files(all_items_found_count)

    print('\nFile name and estimated certificate ID:')
    # print_guessed_cert_id(cert_id)

    #depricated_print_dot_graph_keywordsonly(['rules_cert_id'], all_items_found, cert_id, walk_dir, 'certid_graph_from_keywords.dot', True)

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

    return all_items_found


def extract_file_name_from_url(url):
    file_name = url[url.rfind('/') + 1:]
    file_name = file_name.replace('%20', ' ')
    return file_name


def parse_product_updates(updates_chunk, link_files_updates):
    maintenance_reports = []

    rule_with_maintainance_ST = '.*?([0-9]+?-[0-9]+?-[0-9]+?) (.+?)\<br style=' \
           '.*?\<a href="(.+?)" title="Maintenance Report' \
           '.*?\<a href="(.+?)" title="Maintenance ST'
    rule_without_maintainance_ST = '.*?([0-9]+?-[0-9]+?-[0-9]+?) (.+?)\<br style=' \
           '.*?\<a href="(.+?)" title="Maintenance Report'\

    if updates_chunk.find('Maintenance Report(s)') != -1:
        start_pos = updates_chunk.find('Maintenance Report(s)</div>')
        start_pos = updates_chunk.find('<li>', start_pos)
        while start_pos != -1:
            end_pos = updates_chunk.find('</li>', start_pos)
            report_chunk = updates_chunk[start_pos:end_pos]

            start_pos = updates_chunk.find('<li>', end_pos)

            # decide which search rule to use 1) one that matches also Maintenance ST or 2) without it
            if report_chunk.find('Maintenance ST') != -1:
                rule = rule_with_maintainance_ST
            else:
                rule = rule_without_maintainance_ST

            items_found = {}
            for m in re.finditer(rule, report_chunk):
                match_groups = m.groups()
                index_next_item = 0
                items_found['maintenance_date'] = normalize_match_string(match_groups[index_next_item])
                index_next_item += 1
                items_found['maintenance_item_name'] = normalize_match_string(match_groups[index_next_item])
                index_next_item += 1
                items_found['maintenance_link_cert_report'] = normalize_match_string(match_groups[index_next_item])
                index_next_item += 1
                if len(match_groups) > index_next_item:
                    items_found['maintenance_link_security_target'] = normalize_match_string(match_groups[index_next_item])
                    index_next_item += 1
                else:
                    items_found['maintenance_link_security_target'] = ""

                cert_file_name = extract_file_name_from_url(items_found['maintenance_link_cert_report'])
                items_found['link_cert_report_file_name'] = cert_file_name
                st_file_name = extract_file_name_from_url(items_found['maintenance_link_security_target'])
                items_found['link_security_target_file_name'] = st_file_name

                link_files_updates.append((items_found['maintenance_link_cert_report'], cert_file_name, items_found['maintenance_link_security_target'], st_file_name))

            maintenance_reports.append(items_found)

    return maintenance_reports


def parse_security_level(security_level):
    start_pos = security_level.find('<br>')
    eal_level = security_level
    eal_augmented = []
    if start_pos != -1:
        eal_level = normalize_match_string(security_level[:start_pos])
        # some augmented items found
        augm_chunk = security_level[start_pos:]
        augm_chunk += ' '
        rule = '\<br\>(.+?) '       # items are in form of <br>AVA_VLA.4 <br>AVA_MSU.3 ...

        for m in re.finditer(rule, augm_chunk):
            match_groups = m.groups()
            eal_augmented.append(normalize_match_string(match_groups[0]))

    return eal_level, eal_augmented


def extract_certificates_metadata_html(file_name):
    items_found_all = {}
    download_files_certs = []
    download_files_updates = []
    print('*** {} ***'.format(file_name))

    whole_text = load_cert_html_file(file_name)

    whole_text = whole_text.replace('\n', ' ')
    whole_text = whole_text.replace('&nbsp;', ' ')
    whole_text = whole_text.replace('&amp;', '&')

    # First find end extract chunks between <tr class=""> ... </tr>
    start_pos = whole_text.find('<tfoot class="hilite7"')
    start_pos = whole_text.find('<tr class="', start_pos)

    chunks_found = 0
    chunks_matched = 0

    while start_pos != -1:
        end_pos = whole_text.find('</tr>', start_pos)

        chunk = whole_text[start_pos:end_pos]

        even_start_pos = whole_text.find('<tr class="even">', start_pos + 1)
        odd_start_pos = whole_text.find('<tr class="">', start_pos + 1)

        start_pos = min(even_start_pos, odd_start_pos)

        # skip chunks which are not cert item chunks
        if chunk.find('This list was generated on') != -1:
            continue

        chunks_found += 1

        class HEADER_TYPE(Enum):
            HEADER_FULL = 1
            HEADER_MISSING_VENDOR_WEB = 2

        # IMPORTANT: order regexes based on their specificity - the most specific goes first
        rules_cc_html = [
            (HEADER_TYPE.HEADER_FULL, '\<tr class=(?:""|"even")\>[ ]+\<td class="b"\>(.+?)\<a name="(.+?)" style=.+?\<!-- \<a href="(.+?)" title="Vendor\'s web site" target="_blank"\>(.+?)</a> -->'
            '.+?\<a href="(.+?)" title="Certification Report:.+?" target="_blank" class="button2"\>Certification Report\</a\>'
            '.+?\<a href="(.+?)" title="Security Target:.+?" target="_blank" class="button2">Security Target</a>'
            '.+?\<!-- ------ ------ ------ Product Updates ------ ------ ------ --\>'
            '(.+?)<!-- ------ ------ ------ END Product Updates ------ ------ ------ --\>'
            '.+?\<!--end-product-cell--\>'
            '.+?\<td style="text-align:center"\>\<span title=".+?"\>(.+?)\</span\>\</td\>'
            '.+?\<td style="text-align:center"\>(.*?)\</td\>'
            '[ ]+?\<td>(.+?)\</td\>'),

            (HEADER_TYPE.HEADER_MISSING_VENDOR_WEB,'\<tr class=(?:""|"even")\>[ ]+\<td class="b"\>(.+?)\<a name="(.+?)" style=.+?'
            '.+?\<a href="(.+?)" title="Certification Report:.+?" target="_blank" class="button2"\>Certification Report\</a\>'
            '.+?\<a href="(.+?)" title="Security Target:.+?" target="_blank" class="button2">Security Target</a>'
            '.+?\<!-- ------ ------ ------ Product Updates ------ ------ ------ --\>'
            '(.+?)<!-- ------ ------ ------ END Product Updates ------ ------ ------ --\>'
            '.+?\<!--end-product-cell--\>'
            '.+?\<td style="text-align:center"\>\<span title=".+?"\>(.+?)\</span\>\</td\>'
            '.+?\<td style="text-align:center"\>(.*?)\</td\>'
            '[ ]+?\<td>(.+?)\</td\>'),
        ]

        no_match_yet = True
        for rule in rules_cc_html:
            if not no_match_yet:
                continue    # search only the first match

            rule_and_sep = rule[1]

            for m in re.finditer(rule_and_sep, chunk):
                if no_match_yet:
                    chunks_matched += 1
                    items_found = {}
                    #items_found_all.append(items_found)
                    items_found[TAG_HEADER_MATCH_RULES] = []
                    no_match_yet = False

                # insert rule if at least one match for it was found
                #if rule not in items_found[TAG_HEADER_MATCH_RULES]:
                    # items_found[TAG_HEADER_MATCH_RULES].append(rule[1])

                match_groups = m.groups()

                index_next_item = 0
                items_found['cert_item_name'] = normalize_match_string(match_groups[index_next_item])
                index_next_item += 1
                items_found['cc_cert_item_html_id'] = normalize_match_string(match_groups[index_next_item])
                cert_item_id = items_found['cc_cert_item_html_id']
                index_next_item += 1
                if not rule[0] == HEADER_TYPE.HEADER_MISSING_VENDOR_WEB:
                    items_found['company_site'] = normalize_match_string(match_groups[index_next_item])
                    index_next_item += 1
                    items_found['company_name'] = normalize_match_string(match_groups[index_next_item])
                    index_next_item += 1
                items_found['link_cert_report'] = normalize_match_string(match_groups[index_next_item])
                cert_file_name = extract_file_name_from_url(items_found['link_cert_report'])
                items_found['link_cert_report_file_name'] = cert_file_name
                index_next_item += 1
                items_found['link_security_target'] = normalize_match_string(match_groups[index_next_item])
                st_file_name = extract_file_name_from_url(items_found['link_security_target'])
                items_found['link_security_target_file_name'] = st_file_name
                download_files_certs.append((items_found['link_cert_report'], cert_file_name, items_found['link_security_target'], st_file_name))
                index_next_item += 1

                items_found['maintainance_updates'] = parse_product_updates(match_groups[index_next_item], download_files_updates)
                index_next_item += 1

                items_found['date_cert_issued'] = normalize_match_string(match_groups[index_next_item])
                index_next_item += 1
                items_found['date_cert_expiration'] = normalize_match_string(match_groups[index_next_item])
                index_next_item += 1
                cc_security_level = normalize_match_string(match_groups[index_next_item])
                items_found['cc_security_level'], items_found['cc_security_level_augmented'] = parse_security_level(cc_security_level)
                index_next_item += 1

                # prepare unique name for dictionary (file name is not enough as multiple records reference same cert)
                item_unique_name = '{}__{}'.format(cert_file_name, cert_item_id)
                if item_unique_name not in items_found_all.keys():
                    items_found_all[item_unique_name] = {}
                    items_found_all[item_unique_name]['html_scan'] = items_found
                else:
                    print('{} already in'.format(cert_file_name))

                continue  # we are interested only in first match

        if no_match_yet:
            print('No match found in block #{}'.format(chunks_found))

    print('Chunks found: {}, Chunks matched: {}'.format(chunks_found, chunks_matched))
    if chunks_found != chunks_matched:
        print('WARNING: not all chunks found were matched')

    return items_found_all, download_files_certs, download_files_updates


def check_if_new_or_same(target_dict, target_key, new_value):
    if target_key in target_dict.keys():
        if target_dict[target_key] != new_value:
            if STOP_ON_UNEXPECTED_NUMS:
                raise ValueError('ERROR: Stopping on unexpected intermediate numbers')


def extract_certificates_metadata_csv(file_name):
    items_found_all = {}
    expected_columns = -1
    with open(file_name) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        no_further_maintainance = True
        for row in csv_reader:
            if line_count == 0:
                expected_columns = len(row)
                #print(f'Column names are {", ".join(row)}')
                line_count += 1
            else:
                if no_further_maintainance:
                    items_found = {}
                if len(row) == 0:
                    break
                if len(row) != expected_columns:
                    print('WARNING: Incorrect number of columns in row {} (likely separator , in item name), going to fix...'.format(line_count))
                    # trying to fix
                    if row[4].find('EAL') == -1:
                        row[1] = row[1] + row[2] # fix name
                        row.remove(row[2]) # remove second part of name
                    if len(row[11]) > 0: # test if reassesment is filled
                        if row[13].find('http://') != -1:
                            # name
                            row[11] = row[11] + row[12]
                            row.remove(row[12])

                # check if some maintainance reports are present. If yes, then extract these to list of updates
                if len(row[10]) > 0:
                    no_further_maintainance = False
                else:
                    no_further_maintainance = True

                index_next_item = 0
                check_if_new_or_same(items_found, 'cc_category', normalize_match_string(row[index_next_item]))
                items_found['cc_category'] = normalize_match_string(row[index_next_item])
                index_next_item += 1
                check_if_new_or_same(items_found, 'cert_item_name', normalize_match_string(row[index_next_item]))
                items_found['cert_item_name'] = normalize_match_string(row[index_next_item])
                index_next_item += 1
                check_if_new_or_same(items_found, 'cc_manufacturer', normalize_match_string(row[index_next_item]))
                items_found['cc_manufacturer'] = normalize_match_string(row[index_next_item])
                index_next_item += 1
                check_if_new_or_same(items_found, 'cc_scheme', normalize_match_string(row[index_next_item]))
                items_found['cc_scheme'] = normalize_match_string(row[index_next_item])
                index_next_item += 1
                check_if_new_or_same(items_found, 'cc_security_level', normalize_match_string(row[index_next_item]))
                items_found['cc_security_level'] = normalize_match_string(row[index_next_item])
                index_next_item += 1
                check_if_new_or_same(items_found, 'cc_protection_profiles', normalize_match_string(row[index_next_item]))
                items_found['cc_protection_profiles'] = normalize_match_string(row[index_next_item])
                index_next_item += 1
                check_if_new_or_same(items_found, 'cc_certification_date', normalize_match_string(row[index_next_item]))
                items_found['cc_certification_date'] = normalize_match_string(row[index_next_item])
                index_next_item += 1
                check_if_new_or_same(items_found, 'cc_archived_date', normalize_match_string(row[index_next_item]))
                items_found['cc_archived_date'] = normalize_match_string(row[index_next_item])
                index_next_item += 1
                check_if_new_or_same(items_found, 'link_cert_report', normalize_match_string(row[index_next_item]))
                items_found['link_cert_report'] = normalize_match_string(row[index_next_item])
                link_cert_report = items_found['link_cert_report']

                cert_file_name = extract_file_name_from_url(items_found['link_cert_report'])
                check_if_new_or_same(items_found, 'link_cert_report_file_name', cert_file_name)
                items_found['link_cert_report_file_name'] = cert_file_name
                cert_file_name = items_found['link_cert_report_file_name']
                index_next_item += 1
                check_if_new_or_same(items_found, 'link_security_target', normalize_match_string(row[index_next_item]))
                items_found['link_security_target'] = normalize_match_string(row[index_next_item])
                st_file_name = extract_file_name_from_url(items_found['link_security_target'])
                items_found['link_security_target_file_name'] = st_file_name
                index_next_item += 1

                if 'maintainance_updates' not in items_found:
                    items_found['maintainance_updates'] = []

                maintainance = {}
                maintainance['cc_maintainance_date'] = normalize_match_string(row[index_next_item])
                index_next_item += 1
                maintainance['cc_maintainance_title'] = normalize_match_string(row[index_next_item])
                index_next_item += 1
                maintainance['cc_maintainance_report_link'] = normalize_match_string(row[index_next_item])
                index_next_item += 1
                maintainance['cc_maintainance_st_link'] = normalize_match_string(row[index_next_item])
                index_next_item += 1
                # add this maintainance to parent item only when not empty
                if len(maintainance['cc_maintainance_title']) > 0:
                    items_found['maintainance_updates'].append(maintainance)

                if no_further_maintainance:
                    # prepare unique name for dictionary (file name is not enough as multiple records reference same cert)
                    cert_file_name = cert_file_name.replace('%20', ' ')
                    item_unique_name = cert_file_name
                    item_unique_name = '{}__{}'.format(cert_file_name, line_count)
                    if item_unique_name not in items_found_all.keys():
                        items_found_all[item_unique_name] = {}
                        items_found_all[item_unique_name]['csv_scan'] = items_found
                    else:
                        print('  ERROR: {} already in'.format(cert_file_name))
                        if STOP_ON_UNEXPECTED_NUMS:
                            raise ValueError('ERROR: Stopping as value is not unique')

                line_count += 1

    return items_found_all


def generate_download_script(file_name, certs_dir, targets_dir, download_files_certs):
    with open(file_name, "w") as write_file:
        # certs files
        write_file.write('mkdir \"{}\"\n'.format(certs_dir))
        write_file.write('cd \"{}\"\n\n'.format(certs_dir))
        for cert in download_files_certs:
            write_file.write('curl \"{}\" -o \"{}\"\n'.format(cert[0], cert[1]))
            write_file.write('pdftotext \"{}\"\n\n'.format(cert[1]))

        # security targets file
        write_file.write('\n\ncd ..\n')
        write_file.write('mkdir \"{}\"\n'.format(targets_dir))
        write_file.write('cd \"{}\"\n\n'.format(targets_dir))
        for cert in download_files_certs:
            write_file.write('curl \"{}\" -o \"{}\"\n'.format(cert[2], cert[3]))
            write_file.write('pdftotext \"{}\"\n\n'.format(cert[3]))


def extract_certificates_html(base_dir):
    file_name = '{}cc_products_active.html'.format(base_dir)
    items_found_all_active, download_files_certs, download_files_updates = extract_certificates_metadata_html(file_name)
    for item in items_found_all_active.keys():
        items_found_all_active[item]['html_scan']['cert_status'] = 'active'

    with open("certificate_data_html_active.json", "w") as write_file:
        write_file.write(json.dumps(items_found_all_active, indent=4, sort_keys=True))

    generate_download_script('download_active_certs.bat', 'certs', 'targets', download_files_certs)
    generate_download_script('download_active_updates.bat', 'certs', 'targets', download_files_updates)

    file_name = '{}cc_products_archived.html'.format(base_dir)
    items_found_all_archived, download_files_certs, download_files_updates = extract_certificates_metadata_html(file_name)
    for item in items_found_all_archived.keys():
        items_found_all_archived[item]['html_scan']['cert_status'] = 'archived'

    with open("certificate_data_html_archived.json", "w") as write_file:
        write_file.write(json.dumps(items_found_all_archived, indent=4, sort_keys=True))

    generate_download_script('download_archived_certs.bat', 'certs', 'targets', download_files_certs)
    generate_download_script('download_archived_updates.bat', 'certs', 'targets', download_files_updates)

    items_found_all = {**items_found_all_active, **items_found_all_archived}
    with open("certificate_data_html_all.json", "w") as write_file:
        write_file.write(json.dumps(items_found_all, indent=4, sort_keys=True))

    return items_found_all


def extract_certificates_csv(base_dir):
    file_name = '{}cc_products_active.csv'.format(base_dir)
    items_found_all_active = extract_certificates_metadata_csv(file_name)
    for item in items_found_all_active.keys():
        items_found_all_active[item]['csv_scan']['cert_status'] = 'active'

    file_name = '{}cc_products_archived.csv'.format(base_dir)
    items_found_all_archived = extract_certificates_metadata_csv(file_name)
    for item in items_found_all_archived.keys():
        items_found_all_archived[item]['csv_scan']['cert_status'] = 'archived'

    items_found_all = {**items_found_all_active, **items_found_all_archived}
    with open("certificate_data_csv_all.json", "w") as write_file:
        write_file.write(json.dumps(items_found_all, indent=4, sort_keys=True))

    return items_found_all


def check_expected_cert_results(all_html, all_csv, all_front, all_keywords):
    #
    # CSV
    #
    MIN_ITEMS_FOUND_CSV = 4105
    num_items = len(all_csv)
    if MIN_ITEMS_FOUND_CSV != num_items:
        print('SANITY: different than expected number of CSV records found! ({} vs. {} expected)'.format(num_items, MIN_ITEMS_FOUND_CSV))
        if STOP_ON_UNEXPECTED_NUMS:
            raise ValueError('ERROR: Stopping on unexpected intermediate numbers')

    #
    # HTML
    #
    MIN_ITEMS_FOUND_HTML = 4103
    num_items = len(all_html)
    if MIN_ITEMS_FOUND_HTML != num_items:
        print('SANITY: different than expected number of HTML records found! ({} vs. {} expected)'.format(num_items, MIN_ITEMS_FOUND_HTML))
        if STOP_ON_UNEXPECTED_NUMS:
            raise ValueError('ERROR: Stopping on unexpected intermediate numbers')

    #
    # FRONTPAGE
    #
    MIN_ITEMS_FOUND_FRONTPAGE = 1369
    num_items = len(all_front)
    if MIN_ITEMS_FOUND_FRONTPAGE != num_items:
        print('SANITY: different than expected number of frontpage records found! ({} vs. {} expected)'.format(num_items, MIN_ITEMS_FOUND_FRONTPAGE))
        if STOP_ON_UNEXPECTED_NUMS:
            raise ValueError('ERROR: Stopping on unexpected intermediate numbers')

    #
    # KEYWORDS
    #
    MIN_ITEMS_FOUND_KEYWORDS = 129181
    total_items_found = 0
    for file_name in all_keywords.keys():
        total_items_found += count_num_items_found(all_keywords[file_name])
    if MIN_ITEMS_FOUND_KEYWORDS != total_items_found:
        print('SANITY: different than expected number of keywords found! ({} vs. {} expected)'.format(total_items_found, MIN_ITEMS_FOUND_KEYWORDS))
        if STOP_ON_UNEXPECTED_NUMS:
            raise ValueError('ERROR: Stopping on unexpected intermediate numbers')


def check_expected_pp_results(all_html, all_csv, all_front, all_keywords):
    #
    # CSV
    #
    MIN_ITEMS_FOUND_CSV = 4105
    num_items = len(all_csv)
    if MIN_ITEMS_FOUND_CSV != num_items:
        print('SANITY: different than expected number of CSV records found! ({} vs. {} expected)'.format(num_items, MIN_ITEMS_FOUND_CSV))
        if STOP_ON_UNEXPECTED_NUMS:
            raise ValueError('ERROR: Stopping on unexpected intermediate numbers')

    #
    # HTML
    #
    MIN_ITEMS_FOUND_HTML = 4103
    num_items = len(all_html)
    if MIN_ITEMS_FOUND_HTML != num_items:
        print('SANITY: different than expected number of HTML records found! ({} vs. {} expected)'.format(num_items, MIN_ITEMS_FOUND_HTML))
        if STOP_ON_UNEXPECTED_NUMS:
            raise ValueError('ERROR: Stopping on unexpected intermediate numbers')

    #
    # FRONTPAGE
    #
    MIN_ITEMS_FOUND_FRONTPAGE = 1369
    num_items = len(all_front)
    if MIN_ITEMS_FOUND_FRONTPAGE != num_items:
        print('SANITY: different than expected number of frontpage records found! ({} vs. {} expected)'.format(num_items, MIN_ITEMS_FOUND_FRONTPAGE))
        if STOP_ON_UNEXPECTED_NUMS:
            raise ValueError('ERROR: Stopping on unexpected intermediate numbers')

    #
    # KEYWORDS
    #
    MIN_ITEMS_FOUND_KEYWORDS = 129181
    total_items_found = 0
    for file_name in all_keywords.keys():
        total_items_found += count_num_items_found(all_keywords[file_name])
    if MIN_ITEMS_FOUND_KEYWORDS != total_items_found:
        print('SANITY: different than expected number of keywords found! ({} vs. {} expected)'.format(total_items_found, MIN_ITEMS_FOUND_KEYWORDS))
        if STOP_ON_UNEXPECTED_NUMS:
            raise ValueError('ERROR: Stopping on unexpected intermediate numbers')



def collate_certificates_data(all_html, all_csv, all_front, all_keywords):
    print('\n\nPairing results from different scans ***')

    file_name_to_front_name_mapping = {}
    for long_file_name in all_front.keys():
        short_file_name = long_file_name[long_file_name.rfind('\\') + 1:]
        if short_file_name != '':
            file_name_to_front_name_mapping[short_file_name] = long_file_name

    file_name_to_keywords_name_mapping = {}
    for long_file_name in all_keywords.keys():
        short_file_name = long_file_name[long_file_name.rfind('\\') + 1:]
        if short_file_name != '':
            file_name_to_keywords_name_mapping[short_file_name] = [long_file_name, 0]

    all_cert_items = all_csv
    # pair html data, csv data, front pages and keywords
    for file_name in all_csv.keys():
        pairing_found = False

        file_name_pdf = file_name[:file_name.rfind('__')]
        file_name_txt = file_name_pdf[:file_name_pdf.rfind('.')] + '.txt'
        #file_name_st = all_csv[file_name]['csv_scan']['link_security_target_file_name']
        if 'link_security_target_file_name' in all_csv[file_name]['csv_scan']:
            file_name_st = all_csv[file_name]['csv_scan']['link_security_target_file_name']
        else:
            file_name_st = extract_file_name_from_url(all_csv[file_name]['csv_scan']['link_security_target'])
        file_name_st_txt = file_name_st[:file_name_st.rfind('.')] + '.txt'

        # find all items which references same pdf report
        for file_and_id in all_html.keys():
            # in items extracted from html, names are in form of 'file_name.pdf__number'
            if file_and_id.find(file_name_pdf + '__') != -1:
                if 'processed' not in all_cert_items[file_name].keys():
                    all_cert_items[file_name]['processed'] = {}
                pairing_found = True
                frontpage_scan = None
                keywords_scan = None
                if file_name_txt in file_name_to_front_name_mapping.keys():
                    all_cert_items[file_name]['frontpage_scan'] = all_front[file_name_to_front_name_mapping[file_name_txt]]
                    frontpage_scan = all_front[file_name_to_front_name_mapping[file_name_txt]]
                if file_name_txt in file_name_to_keywords_name_mapping.keys():
                    all_cert_items[file_name]['keywords_scan'] = all_keywords[file_name_to_keywords_name_mapping[file_name_txt][0]]
                    file_name_to_keywords_name_mapping[file_name_txt][1] = 1 # was paired
                    keywords_scan = all_keywords[file_name_to_keywords_name_mapping[file_name_txt][0]]
                if file_name_st_txt in file_name_to_keywords_name_mapping.keys():
                    all_cert_items[file_name]['st_keywords_scan'] = all_keywords[file_name_to_keywords_name_mapping[file_name_st_txt][0]]
                    file_name_to_keywords_name_mapping[file_name_st_txt][1] = 1 # was paired

                all_cert_items[file_name]['processed']['cert_id'] = estimate_cert_id(frontpage_scan, keywords_scan, file_name)

        if not pairing_found:
            print('WARNING: Corresponding HTML report not found for CSV item {}'.format(file_name))

    # pair keywords to maintainance updates
    for file_name in all_csv.keys():
        pairing_found = False

        # process all maintainance updates
        for update in all_cert_items[file_name]['csv_scan']['maintainance_updates']:

            file_name_pdf = extract_file_name_from_url(update['cc_maintainance_report_link'])
            file_name_txt = file_name_pdf[:file_name_pdf.rfind('.')] + '.txt'

            file_name_st = extract_file_name_from_url(update['cc_maintainance_st_link'])
            file_name_st_txt = ''
            if len(file_name_st) > 0:
                file_name_st_txt = file_name_st[:file_name_st.rfind('.')] + '.txt'

            for file_and_id in all_keywords.keys():
                file_name_keyword_txt = file_and_id[file_and_id.rfind('\\') + 1:]
                # in items extracted from html, names are in form of 'file_name.pdf__number'
                if file_name_keyword_txt == file_name_txt:
                    pairing_found = True
                    if file_name_txt in file_name_to_keywords_name_mapping.keys():
                        update['keywords_scan'] = all_keywords[file_name_to_keywords_name_mapping[file_name_txt][0]]
                        if file_name_to_keywords_name_mapping[file_name_txt][1] == 1:
                            print('WARNING: {} already paired'.format(file_name_to_keywords_name_mapping[file_name_txt][0]))
                        file_name_to_keywords_name_mapping[file_name_txt][1] = 1 # was paired

                if file_name_keyword_txt == file_name_st_txt:
                    if file_name_st_txt in file_name_to_keywords_name_mapping.keys():
                        update['st_keywords_scan'] = all_keywords[file_name_to_keywords_name_mapping[file_name_st_txt][0]]
                        if file_name_to_keywords_name_mapping[file_name_st_txt][1] == 1:
                            print('WARNING: {} already paired'.format(file_name_to_keywords_name_mapping[file_name_st_txt][0]))
                        file_name_to_keywords_name_mapping[file_name_st_txt][1] = 1 # was paired

            if not pairing_found:
                print('WARNING: Corresponding keywords pairing not found for maintaince item {}'.format(file_name))


    print('*** Files with keywords extracted, which were NOT matched to any CSV item:')
    for item in file_name_to_keywords_name_mapping:
        if file_name_to_keywords_name_mapping[item][1] == 0: # not paired
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

    print('Records without frontpage: {}\nRecords without keywords: {}'.format(num_frontpage_missing, num_keywords_missing))

    return all_cert_items


def get_manufacturer_simple_name(long_manufacturer, reduction_list):
    if long_manufacturer in reduction_list:
        return reduction_list[long_manufacturer]
    else:
        return long_manufacturer


def process_certificates_data(all_cert_items):
    print('\n\nExtracting useful info from collated files ***')

    #
    # Process 'cc_manufacturer' CSV field
    # 1. separate multiple manufacturers (',' '-' '/' 'and')
    # 2. map different names of a same manufacturer to the same
    manufacturers = []
    for file_name in all_cert_items.keys():
        cert = all_cert_items[file_name]
        # extract manufacturer
        if is_in_dict(cert, ['csv_scan', 'cc_manufacturer']):
            manufacturer = cert['csv_scan']['cc_manufacturer']

            if manufacturer != '':
                if manufacturer not in manufacturers:
                    manufacturers.append(manufacturer)

    sorted_manufacturers = sorted(manufacturers)
    for manuf in sorted_manufacturers:
        print('{}'.format(manuf))

    print('\n\n')
    mapping_csvmanuf_separated = {}
    for manuf in sorted_manufacturers:
        mapping_csvmanuf_separated[manuf] = []

    for manuf in sorted_manufacturers:
        # Manufacturer can be single, multiple, separated by - / and ,
        # heuristics: if separated cnadidate manufacturer can be found in original list (
        # => is sole manufacturer on another certificate => assumption of correct separation)
        separators = [',', '/'] # , '/', ',', 'and']
        multiple_manuf_detected = False
        for sep in separators:
            list_manuf = manuf.split(sep)
            for i in range(0, len(list_manuf)):
                list_manuf[i] = list_manuf[i].strip()
            if len(list_manuf) > 1:
                all_separated_exists = True
                for separated_manuf in list_manuf:
                    if separated_manuf in sorted_manufacturers:
                        continue
                    else:
                        print('Problematic separator \'{}\' in {}'.format(sep, manuf))
                        all_separated_exists = False
                        break

                if all_separated_exists:
                    for x in list_manuf:
                        mapping_csvmanuf_separated[manuf].append(x)
                    multiple_manuf_detected = True

        if not multiple_manuf_detected:
            mapping_csvmanuf_separated[manuf].append(manuf)

    print('### Multiple manufactures detected and split:')
    for manuf in mapping_csvmanuf_separated:
        if len(mapping_csvmanuf_separated[manuf]) > 1:
            print('  {}:{}'.format(manuf, mapping_csvmanuf_separated[manuf]))

    manuf_starts = {}
    already_reduced = {}
    for manuf1 in sorted_manufacturers: # we are processing from the shorter to longer
        if manuf1 == '':
            continue
        for manuf2 in sorted_manufacturers:
            if manuf1 != manuf2:
                if manuf2.startswith(manuf1):
                    print('Potential consolidation of manufacturers: {} vs. {}'.format(manuf1, manuf2))
                    if manuf1 not in manuf_starts:
                        manuf_starts[manuf1] = set()
                    manuf_starts[manuf1].add(manuf2)
                    if manuf2 not in already_reduced:
                        already_reduced[manuf2] = manuf1
                    else:
                        print('  Warning: \'{}\' prefixed by \'{}\' already reduced to \'{}\''.format(manuf2, manuf1, already_reduced[manuf2]))


    # try to find manufacturers with multiple names and draw the map
    dot = Digraph(comment='Manufacturers naming simplifications')
    dot.attr('graph', label='Manufacturers naming simplifications', labelloc='t', fontsize='30')
    dot.attr('node', style='filled')
    already_inserted_edges = []
    for file_name in all_cert_items.keys():
        cert = all_cert_items[file_name]
        if is_in_dict(cert, ['csv_scan', 'cc_manufacturer']):
            joint_manufacturer = cert['csv_scan']['cc_manufacturer']
            if joint_manufacturer != '':
                for manuf in mapping_csvmanuf_separated[joint_manufacturer]:
                    simple_manuf = get_manufacturer_simple_name(manuf, already_reduced)
                    if simple_manuf != manuf:
                        edge_name = '{}<->{}'.format(simple_manuf, manuf)
                        if edge_name not in already_inserted_edges:
                            dot.edge(simple_manuf, manuf, color='orange', style='solid')
                            already_inserted_edges.append(edge_name)

    # plot naming hierarchies
    file_name = 'manufacturer_naming_dependency.dot'
    dot.render(file_name, view=False)
    print('{} pdf rendered'.format(file_name))


    # update dist with processed list of manufactures
    all_cert_items_keys = list(all_cert_items.keys())
    for file_name in all_cert_items_keys:
        cert = all_cert_items[file_name]
        # extract manufacturer
        if is_in_dict(cert, ['csv_scan', 'cc_manufacturer']):
            manufacturer = cert['csv_scan']['cc_manufacturer']

            if manufacturer != '':
                if 'processed' not in cert:
                    cert['processed'] = {}

                # insert extracted manufacturers by full name
                cert['processed']['cc_manufacturer_list'] = mapping_csvmanuf_separated[manufacturer]

                # insert extracted manufacturers by simplified name
                simple_manufacturers = []
                for manuf in mapping_csvmanuf_separated[manufacturer]:
                    simple_manufacturers.append(get_manufacturer_simple_name(manuf, already_reduced))

                cert['processed']['cc_manufacturer_simple_list'] = simple_manufacturers
                cert['processed']['cc_manufacturer_simple'] = get_manufacturer_simple_name(manufacturer, already_reduced)

    return all_cert_items

def generate_dot_graphs(all_items_found, walk_dir):
    print_dot_graph(['rules_cert_id'], all_items_found, walk_dir, 'certid_graph.dot', True)
    print_dot_graph(['rules_javacard'], all_items_found, walk_dir, 'cert_javacard_graph.dot', False)

    #    print_dot_graph(['rules_security_level'], all_items_found, walk_dir, 'cert_security_level_graph.dot', True)
    #    print_dot_graph(['rules_crypto_libs'], all_items_found, walk_dir, 'cert_crypto_libs_graph.dot', False)
    #    print_dot_graph(['rules_vendor'], all_items_found, walk_dir, 'rules_vendor.dot', False)
    #    print_dot_graph(['rules_crypto_algs'], all_items_found, walk_dir, 'rules_crypto_algs.dot', False)
    #    print_dot_graph(['rules_protection_profiles'], all_items_found, walk_dir, 'rules_protection_profiles.dot', False)
    #    print_dot_graph(['rules_defenses'], all_items_found, walk_dir, 'rules_defenses.dot', False)


def generate_basic_download_script():
    with open('download_cc_web.bat', 'w') as file:
        file.write('curl \"https://www.commoncriteriaportal.org/products/\" -o cc_products_active.html\n')
        file.write('curl \"https://www.commoncriteriaportal.org/products/index.cfm?archived=1\" -o cc_products_archived.html\n\n')

        file.write('curl \"https://www.commoncriteriaportal.org/products/certified_products.csv\" -o cc_products_active.csv\n')
        file.write('curl \"https://www.commoncriteriaportal.org/products/certified_products-archived.csv\" -o cc_products_archived.csv\n\n')

        file.write('curl \"https://www.commoncriteriaportal.org/pps/\" -o cc_pp_active.html\n')
        file.write('curl \"https://www.commoncriteriaportal.org/pps/collaborativePP.cfm?cpp=1\" -o cc_pp_collaborative.html\n')
        file.write('curl \"https://www.commoncriteriaportal.org/pps/index.cfm?archived=1\" -o cc_pp_archived.html\n\n')

        file.write('curl \"https://www.commoncriteriaportal.org/pps/pps.csv\" -o cc_pp_active.csv\n')
        file.write('curl \"https://www.commoncriteriaportal.org/pps/pps-archived.csv\" -o cc_pp_archived.csv\n\n')


def main():
    # change current directory to store results into results file
    current_dir = os.getcwd()
    os.chdir(current_dir + '\\..\\results\\')

    cc_html_files_dir = 'c:\\Certs\\web\\'

    walk_dir = 'c:\\Certs\\cc_certs_20191208\\cc_certs\\'
    walk_dir_pp = 'c:\\Certs\\pp_20191213\\'

    #walk_dir = 'c:\\Certs\\cc_certs_test1\\'
    fragments_dir = 'c:\\Certs\\cc_certs_20191208\\cc_certs_txt_fragments\\'

    generate_basic_download_script()

    do_extraction = False
    do_extraction_pp = False
    do_pairing = False
    do_analysis = True

    if do_extraction:
        all_csv = extract_certificates_csv(cc_html_files_dir)
        all_html = extract_certificates_html(cc_html_files_dir)
        all_front = extract_certificates_frontpage(walk_dir)
        all_keywords = extract_certificates_keywords(walk_dir, fragments_dir, 'certificate')

    if do_extraction_pp:
        all_pp_csv = extract_protectionprofiles_csv(cc_html_files_dir)
        all_pp_html = extract_protectionprofiles_html(cc_html_files_dir)
        all_pp_front = extract_protectionprofiles_frontpage(walk_dir_pp)
        all_pp_keywords = extract_certificates_keywords(walk_dir_pp, fragments_dir, 'pp')

    if do_pairing:
        with open('certificate_data_csv_all.json') as json_file:
            all_csv = json.load(json_file)
        with open('certificate_data_html_all.json') as json_file:
            all_html = json.load(json_file)
        with open('certificate_data_frontpage_all.json') as json_file:
            all_front = json.load(json_file)
        with open('certificate_data_keywords_all.json') as json_file:
            all_keywords = json.load(json_file)

        # with open('pp_data_csv_all.json') as json_file:
        #     all_pp_csv = json.load(json_file)
        # with open('pp_data_html_all.json') as json_file:
        #     all_pp_html = json.load(json_file)
        # with open('v_data_frontpage_all.json') as json_file:
        #     all_pp_front = json.load(json_file)
        # with open('pp_data_keywords_all.json') as json_file:
        #     all_pp_keywords = json.load(json_file)

        check_expected_cert_results(all_html, all_csv, all_front, all_keywords)
        all_cert_items = collate_certificates_data(all_html, all_csv, all_front, all_keywords)
        all_cert_items = process_certificates_data(all_cert_items)
        with open("certificate_data_complete.json", "w") as write_file:
            write_file.write(json.dumps(all_cert_items, indent=4, sort_keys=True))

        # check_expected_pp_results(all_pp_html, all_pp_csv, all_pp_front, all_pp_keywords)
        # all_pp_items = collate_pp_data(all_pp_html, all_pp_csv, all_pp_front, all_pp_keywords)
        # with open("pp_data_complete.json", "w") as write_file:
        #     write_file.write(json.dumps(all_pp_items, indent=4, sort_keys=True))

    if do_analysis:
        with open('certificate_data_complete.json') as json_file:
            all_cert_items = json.load(json_file)

        #all_cert_items = process_certificates_data(all_cert_items)

        analyze_cert_years_frequency(all_cert_items)
        analyze_references_graph(['rules_cert_id'], all_cert_items)
        analyze_eal_frequency(all_cert_items)
        analyze_sars_frequency(all_cert_items)
        generate_dot_graphs(all_cert_items, walk_dir)
        plot_certid_to_item_graph(['keywords_scan', 'rules_protection_profiles'], all_cert_items, walk_dir, 'certid_pp_graph.dot', False)

        # with open('pp_data_complete.json') as json_file:
        #     all_pp_items = json.load(json_file)


    # process manufacturer(s) item into 'processed' (one single name + all variants found)
    # extract info about protection profiles, download and parse pdf, map to referencing files
    # analysis of PP only: which PP is the most popular?, what schemes/countries are doing most...
    # analysis of certificates in time (per year) (different schemes)
    # how many certificates are extended? How many times
    # analysis of use of protection profiles
    # analysis of security targets documents
    # analysis of big cert clusters

if __name__ == "__main__":
    main()
