import json
import operator
import random
import string
import os
import datetime
from pathlib import Path

import numpy as np
import matplotlib.pyplot as plt
import copy

from matplotlib.pyplot import figure
from dateutil import parser
from graphviz import Digraph
from tabulate import tabulate

from . import sanity
from .constants import *

plt.rcdefaults()

STOP_ON_UNEXPECTED_NUMS = False

GRAPHS_COLOR_PALETTE = plt.cm.get_cmap('tab20').colors

printable = set(string.printable)


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


def fig_label(title, filter):
    if filter != '':
        return '{}\nfilter: {}'.format(title, filter)
    else:
        return title


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
    plt.close()


def plot_bar_multi_graph(data, x_data_labels, y_label, title, file_name):
    max_len = 0
    for item in data:
        if max_len < len(item):
            max_len = len(item)

    fig_width = round(max_len / 2)
    if fig_width < 10:
        fig_width = 10
    figure(num=None, figsize=(fig_width, 8), dpi=200, facecolor='w', edgecolor='k')
    y_pos = np.arange(len(x_data_labels))
    BAR_WIDTH = 0.4
    for i in range(0, len(data)):
        plt.bar(y_pos + i * BAR_WIDTH, data[i], alpha=0.5, width=BAR_WIDTH)
    plt.xticks(y_pos, x_data_labels)
    plt.xticks(rotation=45)
    plt.ylabel(y_label)
    plt.title(title)
    x1, x2, y1, y2 = plt.axis()
    plt.axis((x1, x2, y1 - 1, y2))
    plt.savefig(file_name + '.png', bbox_inches='tight')
    plt.savefig(file_name + '.pdf', bbox_inches='tight')
    plt.close()


def plot_heatmap_graph(data_matrix, x_data_ticks, y_data_ticks, x_label, y_label, title, file_name):
    fig_size = round(len(x_data_ticks) / 2)
    if fig_size == 0:
        fig_size = 8
    plt.figure(figsize=(fig_size, 8), dpi=200, facecolor='w', edgecolor='k')
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
    try:
        plt.savefig(file_name + '.png', bbox_inches='tight')
    except RuntimeError as e:
        print('RuntimeError while writing {} file as png'.format(file_name + '.png'))
    try:
        plt.savefig(file_name + '.pdf', bbox_inches='tight')
    except RuntimeError as e:
        print('RuntimeError while writing {} file as pdf'.format(file_name + '.pdf'))
    plt.close()


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


def depricated_print_dot_graph_keywordsonly(filter_rules_group, all_items_found, cert_id, filter_label, out_dot_name, thick_as_occurences):
    # print dot
    dot = Digraph(comment='Certificate ecosystem: {}'.format(filter_rules_group))
    dot.attr('graph', label='{}'.format(filter_label), labelloc='t', fontsize='30')
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

        if file_name.rfind(os.sep) != -1:
            just_file_name = file_name[file_name.rfind(os.sep) + 1:]

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


def get_cert_node_label(cert_item, print_item_name):
    if print_item_name:
        sanitized_name = ''.join(filter(lambda x: x in printable, cert_item['csv_scan']['cert_item_name']))
        #sanitized_name = cert_item['csv_scan']['cert_item_name'].encode('ascii', 'ignore')
        #sanitized_name = cert_item['csv_scan']['cert_item_name'].encode("ascii")
        sanitized_name = sanitized_name.replace('&#x3a;', ' ')  # ':' is not allowed in dot
        sanitized_name = sanitized_name.replace('&#x2f;', ' ')  # '/' is not allowed in dot
        return '{}\n{}'.format(cert_item['processed']['cert_id'], sanitized_name)
    else:
        return cert_item['processed']['cert_id']


def print_dot_graph(filter_rules_group, all_items_found, filter_label, out_dot_name, thick_as_occurences, print_item_name, highlight_certs_ids: list):
    # print dot
    dot = Digraph(comment='Certificate ecosystem: {}'.format(filter_rules_group))
    dot.attr('graph', label='{}'.format(filter_label), labelloc='t', fontsize='30')
    dot.attr('node', style='filled')

    # insert nodes believed to be cert id for the processed certificates
    cert_id_to_long_id_map = {}
    for cert_long_id in all_items_found.keys():
        if is_in_dict(all_items_found[cert_long_id], ['processed', 'cert_id']):
            cert_id = all_items_found[cert_long_id]['processed']['cert_id']
            if highlight_certs_ids is not None and cert_id in highlight_certs_ids:
                dot.attr('node', color='red')  # URL='https://www.commoncriteriaportal.org/' doesn't work for pdf
            else:
                dot.attr('node', color='green')

            this_cert_node_label = get_cert_node_label(all_items_found[cert_long_id], print_item_name)
            # basic node id is cert id, but possibly add additional info
            dot.node(all_items_found[cert_long_id]['processed']['cert_id'], label=this_cert_node_label)
            cert_id_to_long_id_map[all_items_found[cert_long_id]['processed']['cert_id']] = cert_long_id

    dot.attr('node', color='gray')
    for cert_long_id in all_items_found.keys():
        # do not continue if no keywords were extracted
        if 'keywords_scan' not in all_items_found[cert_long_id].keys():
            continue

        cert = all_items_found[cert_long_id]
        this_cert_id = ''
        if is_in_dict(cert, ['processed', 'cert_id']):
            this_cert_id = cert['processed']['cert_id']

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
                            #if is_in_dict(cert_id_to_long_id_map, [match]):
                            #    other_cert_node_label = get_cert_node_label(all_items_found[cert_id_to_long_id_map[match]], print_item_name)
                            #else:
                            #    other_cert_node_label = match
                            #dot.edge(this_cert_node_label, other_cert_node_label, color='orange', style='solid', label=label, penwidth=num_occurrences)
                            dot.edge(this_cert_id, match, color='orange', style='solid', label=label, penwidth=num_occurrences)

    # Generate dot graph using GraphViz into pdf
    dot.render(out_dot_name, view=False)

    print('{} pdf rendered'.format(out_dot_name))


def plot_certid_to_item_graph(item_path, all_items_found, filter_label, out_dot_name, thick_as_occurences):
    # print dot
    dot = Digraph(comment='Certificate ecosystem: {}'.format(item_path))
    dot.attr('graph', label='{}'.format(filter_label), labelloc='t', fontsize='30')
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


def build_cert_references(filter_rules_group, all_items_found):
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

    return referenced_by, referenced_by_indirect


def analyze_references_graph(filter_rules_group, all_items_found, filter_label):
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

    # build cert_id to cert_long_id mapping
    cert_id_to_long_id_mapping = {}
    for cert_long_id in all_items_found.keys():
        cert = all_items_found[cert_long_id]
        if is_in_dict(cert, ['processed', 'cert_id']):
            if is_in_dict(cert, ['frontpage_scan', 'cert_item']):
                this_cert_id = cert['processed']['cert_id']
                if this_cert_id in cert_id_to_long_id_mapping.keys():
                    print('ERROR: duplicate cert_id for multiple cert_long_id: {}, {} already used by {}'.format(this_cert_id, cert_long_id, cert_id_to_long_id_mapping[this_cert_id]))
                else:
                    cert_id_to_long_id_mapping[this_cert_id] = cert_long_id

    referenced_by, referenced_by_indirect = build_cert_references(filter_rules_group, all_items_found)

    #
    # process direct references
    #
    referenced_by_direct_nums = {}
    for cert_id in referenced_by.keys():
        referenced_by_direct_nums[cert_id] = len(referenced_by[cert_id])
        if cert_id in cert_id_to_long_id_mapping.keys():
            all_items_found[cert_id_to_long_id_mapping[cert_id]]['processed']['direct_refs'] = len(referenced_by[cert_id])

    print('### Certificates sorted by number of other certificates directly referencing them:')
    sorted_ref_direct = sorted(referenced_by_direct_nums.items(), key=operator.itemgetter(1), reverse=False)
    direct_refs = []
    for cert_id in sorted_ref_direct:
        direct_refs.append(cert_id[1])
        try:
            if is_in_dict(certid_info, [cert_id[0], 'cert_item']):
                print('  {} : {}x directly: {}'.format(cert_id[0], cert_id[1], certid_info[cert_id[0]]['cert_item']))
            else:
                print('  {} : {}x directly'.format(cert_id[0], cert_id[1]))
        except UnicodeEncodeError:
            print('ERROR: UnicodeEncodeError occured')
    print('  Total number of certificates referenced at least once: {}'.format(len(sorted_ref_direct)))

    step = 5
    if len(direct_refs) == 0:
        max_refs = 0
    else:
        max_refs = max(direct_refs) + step
    bins = [1, 2, 3, 4, 5] + list(range(6, max_refs + 1, step))
    compute_and_plot_hist(direct_refs, bins, 'Number of certificates', fig_label('# certificates with specific number of direct references', filter_label), 'cert_direct_refs_frequency.png')

    sanity.check_certs_referenced_once(len(sorted_ref_direct))

    print('### Certificates sorted by number of other certificates indirectly referencing them:')
    referenced_by_indirect_nums = {}
    for cert_id in referenced_by_indirect.keys():
        referenced_by_indirect_nums[cert_id] = len(referenced_by_indirect[cert_id])
        if cert_id in cert_id_to_long_id_mapping.keys():
            all_items_found[cert_id_to_long_id_mapping[cert_id]]['processed']['indirect_refs'] = referenced_by_indirect_nums[cert_id]

    sorted_ref_indirect = sorted(referenced_by_indirect_nums.items(), key=operator.itemgetter(1), reverse=False)
    indirect_refs = []
    for cert_id in sorted_ref_indirect:
        indirect_refs.append(cert_id[1])
        try:
            if is_in_dict(certid_info, [cert_id[0], 'cert_item']):
                print('  {} : {}x indirectly: {}'.format(cert_id[0], cert_id[1], certid_info[cert_id[0]]['cert_item']))
            else:
                print('  {} : {}x indirectly'.format(cert_id[0], cert_id[1]))
        except UnicodeEncodeError:
            print('ERROR: UnicodeEncodeError occured')

    step = 5
    if len(indirect_refs) == 0:
        max_refs = 0
    else:
        max_refs = max(indirect_refs) + step
    bins = [1, 2, 3, 4, 5] + list(range(6, max_refs + 1, step))
    compute_and_plot_hist(indirect_refs, bins, 'Number of certificates', fig_label('# certificates with specific number of indirect references', filter_label), 'cert_indirect_refs_frequency.png')


def plot_schemes_multi_graph(x_ticks, data, prominent_data, x_label, y_label, title, file_name):
    plot_schemes_multi_line_graph(x_ticks, data, prominent_data, x_label, y_label, title, file_name)
    plot_schemes_stacked_graph(x_ticks, data, prominent_data, x_label, y_label, title, file_name + '_stacked')


def plot_schemes_multi_line_graph(x_ticks, data, prominent_data, x_label, y_label, title, file_name):
    figure(num=None, figsize=(16, 8), dpi=200, facecolor='w', edgecolor='k')

    line_types = ['-', ':', '-.', '--']
    num_lines_plotted = 0
    data_sorted = sorted(data.keys())
    color_index = 0
    for group in data_sorted:
        items_in_year = []
        for item in sorted(data[group]):
            num = len(data[group][item])
            items_in_year.append(num)

        if group in prominent_data:
            plt.plot(x_ticks, items_in_year, line_types[num_lines_plotted % len(line_types)],
                     label=group, linewidth=3, color=GRAPHS_COLOR_PALETTE[color_index])
        else:
            # plot non-prominent data as dashed
            plt.plot(x_ticks, items_in_year, line_types[num_lines_plotted % len(line_types)],
                     label=group, linewidth=2, color=GRAPHS_COLOR_PALETTE[color_index])

        # change line type to prevent color repetitions
        num_lines_plotted += 1
        color_index += 1

    plt.rcParams.update({'font.size': 16})
    plt.legend(loc=2)
    plt.xticks(x_ticks, rotation=45)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.title(title)
    plt.savefig(file_name + '.png', bbox_inches='tight')
    plt.savefig(file_name + '.pdf', bbox_inches='tight')
    plt.close()


def plot_schemes_stacked_graph(x_ticks, data, prominent_data, x_label, y_label, title, file_name):
    figure(num=None, figsize=(16, 8), dpi=200, facecolor='w', edgecolor='k')

    # x = range(1, 6)
    # y = [[1, 4, 6, 8, 9], [2, 2, 7, 10, 12], [2, 8, 5, 10, 6]]
    # plt.stackplot(x, y, labels=['A', 'B', 'C'])

    data_stacked = []
    line_types = ['-', ':', '-.', '--']
    num_lines_plotted = 0
    data_sorted = sorted(data.keys())
    for group in data_sorted:
        items_in_year = []
        for item in sorted(data[group]):
            num = len(data[group][item])
            items_in_year.append(num)

        data_stacked.append(items_in_year)

    # if empty data, set as zero
    if len(data_stacked) == 0:
        data_stacked = [0] * len(x_ticks)

    plt.stackplot(x_ticks, data_stacked, colors=GRAPHS_COLOR_PALETTE, labels=data_sorted)

    plt.rcParams.update({'font.size': 16})
    plt.legend(loc=2)
    plt.xticks(x_ticks, rotation=45)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.title(title)
    plt.savefig(file_name + '.png', bbox_inches='tight')
    plt.savefig(file_name + '.pdf', bbox_inches='tight')
    plt.close()


def filter_end_year(items: dict, end_year: int):
    filtered_items = {}

    for item in items.keys():
        filtered_items[item] = {}
        for year in items[item]:
            # copy only years below end_year
            if year <= end_year:
                filtered_items[item][year] = copy.deepcopy(items[item][year])

    return filtered_items


def analyze_cert_years_frequency(all_cert_items, filter_label, force_plot_end_year=None):
    scheme_date = {}
    level_date = {}
    category_date = {}
    pp_date = {}
    labs_date = {}
    archive_date = {}
    validity_length = {}
    valid_in_years = {}
    manufacturer_date = {}
    manufacturer_items = {}
    # START_YEAR = 1997
    START_YEAR = 1995
    END_YEAR = datetime.datetime.now().year + 1
    ARCHIVE_OFFSET = 10

    for i in range(END_YEAR - START_YEAR + ARCHIVE_OFFSET):
        validity_length[i] = []

    valid_in_years['active'] = {}
    valid_in_years['archived'] = {}
    for year in range(START_YEAR, END_YEAR + ARCHIVE_OFFSET):
        valid_in_years['active'][year] = []
        valid_in_years['archived'][year] = []

    for cert_long_id in all_cert_items.keys():
        cert = all_cert_items[cert_long_id]
        if is_in_dict(cert, ['csv_scan', 'cc_certification_date']):
            # extract year of certification
            cert_date = cert['csv_scan']['cc_certification_date']
            if cert_date is None or cert_date == '':
                continue

            parsed_date = parser.parse(cert_date)
            cert_year = parsed_date.year
            # try to extract year of archivation (if provided)
            archived_year = None
            if is_in_dict(cert, ['csv_scan', 'cc_archived_date']):
                cert_archive_date = cert['csv_scan']['cc_archived_date']
                if cert_archive_date != '' and cert_archive_date is not None:
                    archived_year = parser.parse(cert_archive_date).year

            # extract EAL level
            if is_in_dict(cert, ['processed', 'cc_security_level']):
                level_out = cert['processed']['cc_security_level']

                if level_out not in level_date.keys():
                    level_date[level_out] = {}
                    for year in range(START_YEAR, END_YEAR):
                        level_date[level_out][year] = []
                level_date[level_out][cert_year].append(cert_long_id)

            # extract certificate category
            if is_in_dict(cert, ['csv_scan', 'cc_category']):
                category = cert['csv_scan']['cc_category']

                if category not in category_date.keys():
                    category_date[category] = {}
                    for year in range(START_YEAR, END_YEAR):
                        category_date[category][year] = []
                category_date[category][cert_year].append(cert_long_id)

            # extract conformance to protection profile
            if is_in_dict(cert, ['csv_scan', 'cc_protection_profiles']):
                pp_id = cert['csv_scan']['cc_protection_profiles']
                if pp_id == '':
                    pp_id = 'No Protection Profile'
                else:
                    pp_id = 'Protection Profile'
                if pp_id not in pp_date.keys():
                    pp_date[pp_id] = {}
                    for year in range(START_YEAR, END_YEAR):
                        pp_date[pp_id][year] = []
                pp_date[pp_id][cert_year].append(cert_long_id)


            # extract scheme
            if is_in_dict(cert, ['csv_scan', 'cc_scheme']):
                cc_scheme = cert['csv_scan']['cc_scheme']
                if cc_scheme not in scheme_date.keys():
                    scheme_date[cc_scheme] = {}
                    for year in range(START_YEAR, END_YEAR):
                        scheme_date[cc_scheme][year] = []
                scheme_date[cc_scheme][cert_year].append(cert_long_id)

            # extract manufacturer(s)
            if 'cc_manufacturer_simple_list' in cert['processed']:
                for manufacturer in cert['processed']['cc_manufacturer_simple_list']:
                    if manufacturer not in manufacturer_date.keys():
                        manufacturer_date[manufacturer] = {}
                        for year in range(START_YEAR, END_YEAR):
                            manufacturer_date[manufacturer][year] = []
                    if manufacturer not in manufacturer_items:
                        manufacturer_items[manufacturer] = 0

                    manufacturer_date[manufacturer][cert_year].append(cert_long_id)
                    manufacturer_items[manufacturer] += 1

            # extract laboratory
            if is_in_dict(cert, ['processed', 'cert_lab']):
                lab = cert['processed']['cert_lab']

                if lab not in labs_date.keys():
                    labs_date[lab] = {}
                    for year in range(START_YEAR, END_YEAR):
                        labs_date[lab][year] = []
                labs_date[lab][cert_year].append(cert_long_id)

            # extract cert archival status
            if archived_year is not None:
                valid_years = archived_year - cert_year + 1
                validity_length[valid_years].append(cert_long_id)
                cert['processed']['cert_lifetime_length'] = valid_years

                if 'archived_date' not in archive_date.keys():
                    archive_date['archived_date'] = {}
                    for year in range(START_YEAR, END_YEAR + ARCHIVE_OFFSET):  # archive year can be quite in future
                        archive_date['archived_date'][year] = []

                archive_date['archived_date'][archived_year].append(cert_long_id)

            # establish certificates active / archived in give year
            for year in range(START_YEAR, END_YEAR + ARCHIVE_OFFSET):
                if archived_year is not None:
                    # archived date is set
                    if year >= cert_year:
                        if year <= archived_year:
                            # certificate is valid in year
                            valid_in_years['active'][year].append(cert_long_id)
                        else:
                            # certificate is NOT valid in given year
                            valid_in_years['archived'][year].append(cert_long_id)
                else:
                    # no archival date set => active
                    if year >= cert_year:
                        # certificate is valid in year
                        valid_in_years['active'][year].append(cert_long_id)

    # print manufacturers frequency
    sorted_by_occurence = sorted(manufacturer_items.items(), key=operator.itemgetter(1))
    print('\n### Frequency of certificates per company')
    print('  # companies: {}'.format(len(manufacturer_items)))
    print('  # companies with more than 1 cert: {}'.format(len([i for i in sorted_by_occurence if i[1] > 1])))
    print('  # companies with more than 10 cert: {}'.format(len([i for i in sorted_by_occurence if i[1] > 10])))
    print('  # companies with more than 50 cert: {}\n'.format(len([i for i in sorted_by_occurence if i[1] > 50])))
    for manufacturer in sorted_by_occurence:
        print('  {}: {}x'.format(manufacturer[0], manufacturer[1]))

    # plot only top manufacturers
    top_manufacturers = dict(sorted_by_occurence[len(sorted_by_occurence) - 20:]).keys()  # top 20 manufacturers
    top_manufacturers_date = {}
    for manuf in manufacturer_date.keys():
        if manuf in top_manufacturers:
            top_manufacturers_date[manuf] = manufacturer_date[manuf]

    # filter only subset of years if required
    if force_plot_end_year:
        years = np.arange(START_YEAR, force_plot_end_year + 1)
        plot_scheme_date = filter_end_year(scheme_date, force_plot_end_year)
        plot_level_date = filter_end_year(level_date, force_plot_end_year)
        plot_category_date = filter_end_year(category_date, force_plot_end_year)
        plot_pp_date = filter_end_year(pp_date, force_plot_end_year)
        plot_labs_date = filter_end_year(labs_date, force_plot_end_year)
        plot_top_manufacturers_date = filter_end_year(top_manufacturers_date, force_plot_end_year)
    else:
        # plot all
        years = np.arange(START_YEAR, END_YEAR)
        plot_scheme_date = scheme_date
        plot_level_date = level_date
        plot_category_date = category_date
        plot_pp_date = pp_date
        plot_labs_date = labs_date
        plot_top_manufacturers_date = top_manufacturers_date

    sc_manufacturers = ['Gemalto', 'NXP Semiconductors', 'Samsung', 'STMicroelectronics', 'Oberthur Technologies',
                        'Infineon Technologies AG', 'G+D Mobile Security GmbH', 'ATMEL Smart Card ICs', 'Idemia',
                        'Athena Smartcard', 'Renesas', 'Philips Semiconductors GmbH', 'Oberthur Card Systems']

    # plot graphs showing cert. scheme and EAL in years
    plot_schemes_multi_graph(years, plot_scheme_date, ['DE', 'JP', 'FR', 'US', 'CA'], 'Year of issuance', 'Number of certificates issued', fig_label('CC certificates issuance frequency per scheme and year', filter_label), 'num_certs_in_years')
    plot_schemes_multi_graph(years, plot_level_date, ['EAL4+', 'EAL5+','EAL2+', 'Protection Profile'], 'Year of issuance', 'Number of certificates issued', fig_label('Certificates issuance frequency per level and year', filter_label), 'num_certs_level_in_years')
    plot_schemes_multi_graph(years, plot_category_date, [], 'Year of issuance', 'Number of certificates issued', fig_label('Category of certificates issued in given year', filter_label), 'num_certs_category_in_years')
    plot_schemes_multi_graph(years, plot_pp_date, [], 'Year of issuance', 'Number of certificates issued', fig_label('Certificates conforming to Protection Profile(s)', filter_label), 'num_certs_pp_in_years')
    plot_schemes_multi_graph(years, plot_labs_date, [], 'Year of issuance', 'Number of certificates issued', fig_label('Number of certificates certified by laboratory in given year', filter_label), 'num_certs_by_lab_in_years')
    plot_schemes_multi_graph(years, plot_top_manufacturers_date, sc_manufacturers, 'Year of issuance', 'Number of certificates issued', fig_label('Top 20 manufacturers of certified items per year', filter_label), 'manufacturer_in_years')

    # plot stats with extended range
    years_extended = np.arange(START_YEAR, END_YEAR + ARCHIVE_OFFSET)
    plot_schemes_multi_graph(years_extended, archive_date, [], 'Year of issuance', 'Number of certificates', fig_label('Number of certificates archived or planned for archival in a given year', filter_label), 'num_certs_archived_in_years')
    plot_schemes_multi_graph(years_extended, valid_in_years, [], 'Year', 'Number of certificates', fig_label('Number of certificates active and archived in given year', filter_label), 'num_certs_active_archived_in_years')

    # plot certificate validity lengths
    print('### Certificates validity period lengths:')
    validity_length_numbers = []
    for length in sorted(validity_length.keys()):
        print('  {} year(s): {}x   {}'.format(length, len(validity_length[length]), validity_length[length]))
        validity_length_numbers.append(len(validity_length[length]))
    plot_bar_graph(validity_length_numbers, sorted(validity_length.keys()), 'Number of certificates', fig_label('Number of certificates with specific validity length', filter_label), 'cert_validity_length_frequency')


def analyze_eal_frequency(all_cert_items, filter_label):
    scheme_level = {}
    for cert_long_id in all_cert_items.keys():
        cert = all_cert_items[cert_long_id]
        if is_in_dict(cert, ['csv_scan', 'cc_scheme']):
            if is_in_dict(cert, ['processed', 'cc_security_level']):
                cc_scheme = cert['csv_scan']['cc_scheme']
                level = cert['processed']['cc_security_level']
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
    eal_headers = ['EAL0+', 'EAL1', 'EAL1+','EAL2', 'EAL2+', 'EAL3', 'EAL3+', 'EAL4', 'EAL4+', 'EAL5',
                   'EAL5+', 'EAL6', 'EAL6+', 'EAL7', 'EAL7+', 'None']

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
    plot_bar_graph(total_eals_row, eal_headers, 'Number of certificates', fig_label('Number of certificates of specific EAL level', filter_label), 'cert_eal_frequency')

    # Print table with results over national schemes
    total_eals_row.append(sum_total)
    cc_eal_freq.append(['Total'] + total_eals_row)
    print(tabulate(cc_eal_freq, ['CC scheme'] + eal_headers + ['Total']))


def analyze_pdfmeta(all_cert_items, filter_label):
    pdf_tags = {}
    pdf_values = {}
    for cert_long_id in all_cert_items.keys():
        cert = all_cert_items[cert_long_id]

        if is_in_dict(cert, ['pdfmeta_scan']):
            pdf_scan = cert['pdfmeta_scan']
            for tag in pdf_scan.keys():
                if tag not in pdf_tags.keys():
                    pdf_tags[tag] = 1  # count number of occurence of particular pdf tag
                    pdf_values[tag] = {} # collect values for particular tag and their frequencies
                    pdf_values[tag][pdf_scan[tag]] = [cert_long_id]
                else:
                    pdf_tags[tag] += 1
                    if pdf_scan[tag] not in pdf_values[tag].keys():
                        pdf_values[tag][pdf_scan[tag]] = [cert_long_id]
                    else:
                        pdf_values[tag][pdf_scan[tag]].append(cert_long_id)


    print('\n### Extracted pdf tags frequency:')
    sorted_by_occurence = sorted(pdf_tags.items(), key=operator.itemgetter(1))
    for tag in sorted_by_occurence:
        print('{:10}: {}x'.format(tag[0], tag[1]))
        if tag[0] in ['pdf_file_size_bytes', '/ModDate', 'pdf_number_of_pages', '/CreationDate']:
            print('  Would be too many separate outputs, print supressed')
        else:
            detected_items_count = {}
            for item in pdf_values[tag[0]].items():
                detected_items_count[item[0]] = len(item[1])
            sorted_by_occurence_values = sorted(detected_items_count.items(), key=operator.itemgetter(1))
            for value in sorted_by_occurence_values:
                print('  {:10}: {}x : {}'.format(value[0], value[1], pdf_values[tag[0]][value[0]]))


def analyze_security_assurance_component_frequency(all_cert_items, filter_label):
    return analyze_sc_frequency(all_cert_items, filter_label, 'assurance')


def analyze_security_functional_component_frequency(all_cert_items, filter_label):
    return analyze_sc_frequency(all_cert_items, filter_label, 'functional')


def analyze_sc_frequency(all_cert_items, filter_label, sec_component_label):
    sars_freq = {}
    key_name = 'invalid'
    shortcut = 'invalid'
    if sec_component_label == 'functional':
        key_name = 'rules_security_functional_components'
        shortcut = 'sfr'
    if sec_component_label == 'assurance':
        key_name = 'rules_security_assurance_components'
        shortcut = 'sar'

    for cert_long_id in all_cert_items.keys():
        cert = all_cert_items[cert_long_id]
        if is_in_dict(cert, ['keywords_scan', key_name]):
            sars = cert['keywords_scan'][key_name]
            for sar_rule in sars:
                for sar_hit in sars[sar_rule]:
                    if sar_hit not in sars_freq.keys():
                        sars_freq[sar_hit] = 0
                    sars_freq[sar_hit] += 1

    print('\n### CC security ' + sec_component_label + ' components frequency:')
    sars_labels = sorted(sars_freq.keys())
    sars_freq_nums = []
    for sar in sars_labels:
        print('{:10}: {}x'.format(sar, sars_freq[sar]))
        sars_freq_nums.append(sars_freq[sar])

    print('\n### CC security ' + sec_component_label + ' components frequency sorted by num occurences:')
    sorted_by_occurence = sorted(sars_freq.items(), key=operator.itemgetter(1))
    for sar in sorted_by_occurence:
        print('{:10}: {}x'.format(sar[0], sar[1]))

    # plot bar graph with frequency of CC SARs
    plot_bar_graph(sars_freq_nums, sars_labels, 'Number of certificates', fig_label('Number of certificates mentioning specific security ' + sec_component_label + ' component (' + shortcut + ')\nAll listed occured at least once', filter_label), 'cert_' + shortcut + '_frequency')
    if len(sars_freq_nums) > 0 and len(sars_labels) > 0:
        sars_freq_nums, sars_labels = (list(t) for t in zip(*sorted(zip(sars_freq_nums, sars_labels), reverse=True)))
        plot_bar_graph(sars_freq_nums, sars_labels, 'Number of certificates', fig_label(
            'Number of certificates mentioning specific security ' + sec_component_label + ' component (' + shortcut + ')\nAll listed occured at least once',
            filter_label), 'cert_' + shortcut + '_frequency_sorted')
    else:
        print('ERROR: len(sars_freq_nums) < 1')

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
    max_sar_level = 8
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
            level_str = sar[0][sar[0].find('.') + 1:]
            if level_str.find('.') != -1:   # level can have multiple subparts (e.g., ACE_ECD.1.1)
                level_str = level_str[:level_str.find('.')]  # extract only the first one
            level = int(level_str)
            sar_matrix[level - 1][name_index] = sar[1]

    # plot heatmap graph with frequency of SAR levels
    y_data_labels = range(1, max_sar_level + 2)
    plot_heatmap_graph(sar_matrix, sars_unique_names, y_data_labels, 'Security ' + sec_component_label + ' component (' + shortcut + ') class', 'Security ' + sec_component_label + ' components (' + shortcut + ') level', fig_label('Frequency of achieved levels for Security ' + sec_component_label + ' component (' + shortcut + ') classes', filter_label), 'cert_' + shortcut + '_heatmap')


def generate_dot_graphs(all_items_found, filter_label, highlight_certs_id=None):
    # with name of certified items
    print_dot_graph(['rules_cert_id'], all_items_found, filter_label, 'certidname_graph.dot', True, True, highlight_certs_id)
    # without name of certified items
    print_dot_graph(['rules_cert_id'], all_items_found, filter_label, 'certid_graph.dot', True, False, highlight_certs_id)
    # link between device and its javacard version
    print_dot_graph(['rules_javacard'], all_items_found, filter_label, 'cert_javacard_graph.dot', False, True, highlight_certs_id)

    #    print_dot_graph(['rules_security_level'], all_items_found, filter_label, 'cert_security_level_graph.dot', True)
    #    print_dot_graph(['rules_crypto_libs'], all_items_found, filter_label, 'cert_crypto_libs_graph.dot', False)
    #    print_dot_graph(['rules_vendor'], all_items_found, filter_label, 'rules_vendor.dot', False)
    #    print_dot_graph(['rules_crypto_algs'], all_items_found, filter_label, 'rules_crypto_algs.dot', False)
    #    print_dot_graph(['rules_protection_profiles'], all_items_found, filter_label, 'rules_protection_profiles.dot', False)
    #    print_dot_graph(['rules_defenses'], all_items_found, filter_label, 'rules_defenses.dot', False)


def do_all_analysis(all_cert_items, filter_label, highlight_certs_id = None):
    analyze_cert_years_frequency(all_cert_items, filter_label)
    analyze_references_graph(['rules_cert_id'], all_cert_items, filter_label)
    analyze_eal_frequency(all_cert_items, filter_label)
    analyze_security_assurance_component_frequency(all_cert_items, filter_label)
    analyze_security_functional_component_frequency(all_cert_items, filter_label)
    analyze_pdfmeta(all_cert_items, filter_label)
    plot_certid_to_item_graph(['keywords_scan', 'rules_protection_profiles'], all_cert_items, filter_label, 'certid_pp_graph.dot', False)
    generate_dot_graphs(all_cert_items, filter_label, highlight_certs_id)


def do_analysis_everything(all_cert_items, current_dir: Path):
    if not os.path.exists(current_dir):
        os.makedirs(current_dir)
    os.chdir(current_dir)
    do_all_analysis(all_cert_items, '')


def do_analysis_09_01_2019_archival(all_cert_items, current_dir: Path):
    target_folder = os.path.join(current_dir, 'results_archived01092019_only')
    if not os.path.exists(target_folder):
        os.makedirs(target_folder)
    os.chdir(target_folder)
    archived_date = '09/01/2019'
    limited_cert_items = {x: all_cert_items[x] for x in all_cert_items if is_in_dict(all_cert_items[x], ['csv_scan', 'cc_archived_date']) and all_cert_items[x]['csv_scan']['cc_archived_date'] == archived_date}
    do_all_analysis(limited_cert_items, 'cc_archived_date={}'.format(archived_date))


def do_analysis_force_end_date(all_cert_items, current_dir: Path, force_end_date: int):
    target_folder = os.path.join(current_dir, 'results_in_years_only_till_{}'.format(force_end_date))
    if not os.path.exists(target_folder):
        os.makedirs(target_folder)
    os.chdir(target_folder)
    analyze_cert_years_frequency(all_cert_items, '', force_end_date)


def do_analysis_affected(all_cert_items: dict, results_dir: Path, target_certs_id: list, set_name_label: str):
    # build references graph
    referenced_by_direct, referenced_by_indirect = build_cert_references(['rules_cert_id'], all_cert_items)

    # extract only such references which are relevant to target_certs_id
    filter_direct = set()
    filter_indirect = set()
    for target_cert_id in target_certs_id:
        if target_cert_id in referenced_by_direct:
            filter_direct.update(referenced_by_direct[target_cert_id])
        if target_cert_id in referenced_by_indirect:
            filter_indirect.update(referenced_by_indirect[target_cert_id])

    # add also target_certs_id into list of certificates to analyze
    filter_direct.update(target_certs_id)
    filter_indirect.update(target_certs_id)

    label = get_label_from_certids(target_certs_id)
    filter_and_do_all_analysis_filtered(all_cert_items, target_certs_id, target_certs_id, results_dir,
                                        '{}_target_id_{}'.format(set_name_label, label))
    filter_and_do_all_analysis_filtered(all_cert_items, filter_direct, target_certs_id, results_dir,
                                        '{}_directly_referring_to_{}'.format(set_name_label, label))
    filter_and_do_all_analysis_filtered(all_cert_items, filter_indirect, target_certs_id, results_dir,
                                        '{}_indirectly_referring_to_{}'.format(set_name_label, label))


def get_label_from_certids(target_certs_id: list):
    # concatenate all target ids into single string label
    label = ''
    for target_id in target_certs_id:
        target_id_sanitized = target_id.replace('\\', '')
        target_id_sanitized = target_id_sanitized.replace('/', '')
        label = label + target_id_sanitized + '__'
    MAX_LABEL_LENGTH = 100
    if len(label) > MAX_LABEL_LENGTH:
        label = label[:MAX_LABEL_LENGTH - 6] + '__more'

    return label


def filter_and_do_all_analysis_filtered(all_cert_items: dict, target_certs_id: list, highlight_certs_id: list,
                                        results_dir: Path, label: str):
    target_cert_items = {x: all_cert_items[x] for x in all_cert_items if
                                    is_in_dict(all_cert_items[x], ['processed', 'cert_id']) and
                                    all_cert_items[x]['processed']['cert_id'] in target_certs_id}
    do_all_analysis_filtered(target_cert_items, results_dir, label, highlight_certs_id)


def do_analysis_affecting(all_cert_items: dict, results_dir: Path, target_certs_id: list, set_name_label: str):
    # build references graph
    referenced_by_direct, referenced_by_indirect = build_cert_references(['rules_cert_id'], all_cert_items)

    # extract only such references which are relevant to target_certs_id
    # idea - loop over all cert ids, add to set when target id(s) is referenced
    filter_direct = set()
    filter_indirect = set()

    for cert_id in referenced_by_direct.keys():
        for target_cert_id in target_certs_id:
            if target_cert_id in referenced_by_direct[cert_id]:
                filter_direct.update([cert_id])

    for cert_id in referenced_by_indirect.keys():
        for target_cert_id in target_certs_id:
            if target_cert_id in referenced_by_indirect[cert_id]:
                filter_indirect.update([cert_id])

    # add also target_certs_id into list of certificates to analyze
    filter_direct.update(target_certs_id)
    filter_indirect.update(target_certs_id)

    label = get_label_from_certids(target_certs_id)
    filter_and_do_all_analysis_filtered(all_cert_items, target_certs_id, target_certs_id, results_dir,
                                        '{}_target_id_{}'.format(set_name_label, label))
    filter_and_do_all_analysis_filtered(all_cert_items, filter_direct, target_certs_id, results_dir,
                                        '{}_directly_referenced_by{}'.format(set_name_label, label))
    filter_and_do_all_analysis_filtered(all_cert_items, filter_indirect, target_certs_id, results_dir,
                                        '{}_indirectly_referenced_by_{}'.format(set_name_label, label))


def do_all_analysis_filtered(limited_cert_items, current_dir: Path, filter_label: str, highlight_certs_id: list):
    target_folder = os.path.join(current_dir, filter_label)
    if not os.path.exists(target_folder):
        os.makedirs(target_folder)
    os.chdir(target_folder)
    with open(Path(target_folder) / "certificate_data_complete_processed_analyzed.json", "w") as write_file:
        json.dump(limited_cert_items, write_file, indent=4, sort_keys=True)
    do_all_analysis(limited_cert_items, filter_label, highlight_certs_id)


def do_analysis_manufacturers(all_cert_items, current_dir: Path):
    # analyze only Infineon certificates
    do_analysis_only_filtered(all_cert_items, current_dir,
                              ['processed', 'cc_manufacturer_simple'], 'Infineon Technologies AG')
    # analyze only NXP certificates
    do_analysis_only_filtered(all_cert_items, current_dir,
                          ['processed', 'cc_manufacturer_simple'], 'NXP Semiconductors')
    # analyze only Red Hat certificates
    do_analysis_only_filtered(all_cert_items, current_dir,
                              ['processed', 'cc_manufacturer_simple'], 'Red Hat, Inc')
    # analyze only Suse certificates
    do_analysis_only_filtered(all_cert_items, current_dir,
                              ['processed', 'cc_manufacturer_simple'], 'SUSE Linux Products Gmbh')


def do_analysis_only_filtered(all_cert_items, current_dir: Path, filter_path, filter_value):
    filter_string = ''
    for item in filter_path:
        if len(filter_string) > 0:
            filter_string = filter_string + '__'
        filter_string = filter_string + item
    target_folder = current_dir / '{}={}'.format(filter_string, filter_value)
    if not os.path.exists(target_folder):
        os.makedirs(target_folder)
    os.chdir(target_folder)

    cert_items = filter_items(all_cert_items, filter_path, filter_value)

    print(len(cert_items))
    do_all_analysis(cert_items, '{}={}'.format(filter_string, filter_value))


def do_analysis_only_category(all_cert_items, current_dir: Path, category):
    do_analysis_only_filtered(all_cert_items, current_dir, ['csv_scan', 'cc_category'], category)


def do_analysis_only_smartcards(all_cert_items, current_dir: Path):
    do_analysis_only_category(all_cert_items, current_dir, 'ICs, Smart Cards and Smart Card-Related Devices and Systems')


def do_analysis_only_operatingsystems(all_cert_items, current_dir: Path):
    do_analysis_only_category(all_cert_items, current_dir, 'Operating Systems')


def transform_fips_to_cc_dict(all_cert_items_fips):
    all_cert_items_cc = {}

    exceptions_items = {}
    certs = all_cert_items_fips["certs"]
    for cert_item_key in certs.keys():
        fips_item = certs[cert_item_key]

        cc_item = {}
        cc_item["csv_scan"] = {}
        cc_item["frontpage_scan"] = {}
        cc_item["keywords_scan"] = {}
        cc_item["pdfmeta_scan"] = {}
        cc_item["processed"] = {}

        cc_item["processed"]["cc_manufacturer_list"] = fips_item["vendor"]
        cc_item['processed']['cc_manufacturer_simple_list'] = [fips_item["vendor"]]
        cc_item["processed"]["cert_id"] = fips_item["cert_id"]
        cc_item["processed"]["cert_lab"] = fips_item["lab"]
        if fips_item["exceptions"] is None:
            cc_item["processed"]["cc_security_level"] = 'Level ' + fips_item["level"]
        else:
            cc_item["processed"]["cc_security_level"] = 'Level ' + fips_item["level"] + '+'

        cc_item['csv_scan']['cc_scheme'] = 'NIST'
        cc_item["csv_scan"]["cc_certification_date"] = fips_item["date_validation"][0]
        cc_item["csv_scan"]["cc_archived_date"] = fips_item["date_sunset"]
        cc_item["csv_scan"]["cc_category"] = '{} {}'.format(fips_item["type"], fips_item["embodiment"])

        cc_item["processed"]["cc_security_level_augments"] = []
        if fips_item["exceptions"]:
            for exception in fips_item["exceptions"]:
                try:
                    ex_name, ex_level = exception.split(':')
                    ex_name = ex_name.strip()
                    ex_level = ex_level.strip()

                    # collect all items seen
                    exceptions_items[ex_name] = exceptions_items.get(ex_name, [])
                    exceptions_items[ex_name].append(ex_level)

                    # save augments
                    if ex_level.find("evel") != -1:
                        cc_item["processed"]["cc_security_level_augments"].append('{}.{}'.format(ex_name, ex_level))

                except ValueError as e:
                    print(exception)

        all_cert_items_cc[cert_item_key] = cc_item

    return all_cert_items_cc


def do_analysis_fips_certs(all_cert_items_fips, current_dir: Path):
    all_cert_items = transform_fips_to_cc_dict(all_cert_items_fips)
    with open(current_dir / "fips_transformed_cc.json", "w") as write_file:
        json.dump(all_cert_items, write_file, indent=4, sort_keys=True)

    target_folder = os.path.join(current_dir, 'fips')
    if not os.path.exists(target_folder):
        os.makedirs(target_folder)
    os.chdir(target_folder)

    analyze_cert_years_frequency(all_cert_items, '')
    do_analysis_force_end_date(all_cert_items, target_folder, 2020)


def get_name_for_keyword_search_results(do_find_affected_keywords: list):
    # save list of found cert ids to separate json
    first_keyword = (do_find_affected_keywords[0]).replace('\\', '')  # get first sanitized search keyword
    file_name = "find_keyword__{}_{}__{}".format(
        first_keyword,
        '' if len(do_find_affected_keywords) == 1 else 'and_more_(len_{})'.format(len(do_find_affected_keywords)),
        random.randint(0, 1000000))  # just for randomization of file name
    return file_name


def process_matched_keywords(all_cert_items: dict, all_keywords: dict, do_find_affected_keywords: list, results_dir: Path):
    certs_with_keywords = {'keywords': do_find_affected_keywords, 'certs': {}}
    for item in all_keywords.keys():
        if len(all_keywords[item]['keyword']) > 0:
            # this file contains required keyword

            # extract cert name to search for
            cert_file_name = item[item.rfind('\\') + 1:]
            cert_file_name = cert_file_name[:cert_file_name.find('.')]
            cert_file_name = cert_file_name + '.pdf__'  # make file name
            # find this file in processed results
            for cert_item_name in all_cert_items.keys():
                if cert_item_name.find(cert_file_name) != -1:  # check if starts with provided file name
                    if is_in_dict(all_cert_items[cert_item_name], ['processed', 'cert_id']):
                        cert_id = all_cert_items[cert_item_name]['processed']['cert_id']
                        certs_with_keywords['certs'][cert_id] = item
                        # do_find_affected = do_find_affected + (cert_id,)

    certs_with_keywords['total_match_files'] = len(certs_with_keywords['certs'])


    return certs_with_keywords


def filter_items(items: dict, filter_path: list, filter_value: str):
    filtered_items = {}
    for item_key in items.keys():
        item = get_item_from_dict(items[item_key], filter_path)
        if item is not None:
            if item == filter_value:
                # Match found, include
                filtered_items[item_key] = items[item_key]

    return filtered_items
