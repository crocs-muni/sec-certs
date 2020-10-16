import datetime
import re
import sys
from collections import OrderedDict
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

from pp_matcher import read_json_results, pp_read_mapping, read_active_product_csv
from pp_tags_constants import *

# TODO uncomment the following to use functions from sec-certs project used in create_statistics
#sys.path.insert(1, str(Path('../../sec-certs-master/src/')))

#import analyze_certificates

RESULT_DIR = Path('../results/')
PP_FRONTPAGE_RESULT = RESULT_DIR / 'pp_data_frontpage_all.json'
PP_COMPLETE_RESULT = RESULT_DIR / 'pp_data_complete.json'


# class representing a protection profile storing data we gathered from scans
# big adventage when using from console!
# PP_NEW
class ProtectionProfile:

    def __init__(self, pp_filename, pp_csv_scan, pp_frontpage_scan):
        self.pp_filename = pp_filename
        self.pp_csv_scan = pp_csv_scan
        self.pp_frontpage_scan = pp_frontpage_scan
        self.refered_count = 0
        self.product_csv_lines = []
        self.pp_reference_ids = set()

    def add_reference(self, reference_id, product_csv_line):
        self.refered_count += 1
        self.pp_reference_ids.add(reference_id)
        self.product_csv_lines.append(product_csv_line)

# PP_NEW
def build_complex_refferences(pp_scan_complete, cc_product_csv, mapping):
    """
    from data gathered by scans build dictionary of protectionProfile objects
    :param pp_scan_complete: dictionary read from pp_data_complete.json
    :param cc_product_csv: list of lines of active CC product CSV
    :param mapping: mapping of PP referrences to PP filenames
    :return: returns dictionary of all PPs and dictionary of PPs that are referred at least once
    """

    all_pps = {}
    refered_pps = {}

    print('*** Building complex references objects ***')

    for pp in pp_scan_complete:
        pp_data = pp_scan_complete[pp]
        if pp_data is None:
            print('Warning: No PP information data found for PP with filename {}.'.format(pp))
            continue

        if 'frontpage_scan' in pp_data:
            front_page_scan = pp_data['frontpage_scan']
        else:
            print('INFO: frontpage_scan missing for PP with filename {}'.format(pp))
            front_page_scan = {}

        all_pps[Path(pp).stem] = ProtectionProfile(Path(pp).stem, pp_data['csv_scan'], front_page_scan)

    for line in cc_product_csv:
        if line['Protection Profile(s)'] is not None and line['Protection Profile(s)'] != '':
            references = line['Protection Profile(s)'].split(',')
            for reference in references:

                if reference not in mapping:
                    print('WARNING: no mapping for reference {}'.format(reference))
                    continue

                if mapping[reference] not in all_pps:
                    print('WARNING: The reference {} with mapping to PP {} not in PP scan json result'
                          .format(reference, mapping[reference]))
                    continue

                pp_data = all_pps[mapping[reference]]

                if reference not in refered_pps:
                    refered_pps[reference] = pp_data

                refered_pps[reference].add_reference(reference, line)

    refered_pps = {k: v for k, v in sorted(refered_pps.items(), reverse=True, key=lambda ref: ref[1].refered_count)}

    print('\n\n')
    return all_pps, refered_pps

# PP_NEW
def get_refered_pps_frequency(referred_pps):
    """
    builds frequency dictionary of referred pps
    :param refered_pps: dictionary with keys names of PPs and values protectionProfile objects
    :return: frequency dictionary
    """

    freq_dict = {}

    for pp in referred_pps.values():
        if pp.pp_filename not in freq_dict:
            freq_dict[pp.pp_filename] = pp.refered_count

    print('*** PP usage frequency (stemmed PP filenames) ***')
    for pp in freq_dict:
        print('{}: {}'.format(pp, freq_dict[pp]))

    print('\n\n')
    return freq_dict

# PP_NEW
def basic_characteristics(pp_ref_frequency):
    """
    prints basic characteristics of random variable
    :param pp_ref_frequency: frequency dictionary of referred PPs
    :return: void
    """
    sample = list(pp_ref_frequency.values())
    print('*** Basic characteristics of PP usage ***')
    size = len(sample)
    print('Sample Size: {}'.format(size))
    minimum = min(sample)
    print('Sample minimum: {}'.format(minimum))
    maximum = max(sample)
    print('Sample maximum: {}'.format(maximum))
    mean = sum(sample) / size
    print('Sample mean: {}'.format(mean))
    quartiles = np.percentile(sample, [25, 50, 75])
    print('1Q: {}'.format(quartiles[0]))
    print('Sample median: {}'.format(quartiles[1]))
    print('3Q: {}'.format(quartiles[2]))
    variance = np.var(sample)
    print('Sample variance: {}'.format(variance))
    print('Standard deviation: {}\n\n'.format(np.sqrt(variance)))

# PP_NEW
def reference_hist(freqencies_dict):
    """
    prints histogram of PP references
    :param freqencies_dict: frequency dictionary of referred PPs
    :return: void
    """

    freq = [freqencies_dict[x] for x in freqencies_dict]

    fig, ax = plt.subplots()
    plt.hist(x=freq, bins='auto', color='skyblue')
    plt.grid(axis='y', alpha=0.75)
    #plt.xscale('log', basex=2)
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda y, _: '{:g}'.format(y)))
    plt.xlabel('Value')
    plt.ylabel('Frequency')
    ax.set_title('Histogram of PP usage.')

    plt.savefig(RESULT_DIR / 'pp_referrence_frequency_histogram.png')
    plt.show()

# PP_NEW
def reference_boxplot(frequencies_dict):
    """
    prints boxplot of random variable
    :param frequencies_dict: frequency dictionary of referred PPs
    :return: void
    """

    freq = [frequencies_dict[x] for x in frequencies_dict]

    fig, ax = plt.subplots()
    #red_square = dict(markerfacecolor='r', marker='s')

    plt.boxplot(freq, notch=True, vert=False, showmeans=True) #filterpos=red_square
    ax.set_title('Protection Profile reference frequency boxplot.')
    plt.xscale('log', basex=2)
    plt.xlabel('Number of references from different ST (log scale)')
    plt.yticks(np.arange(1), 'PP')
    plt.ylabel('Protection Profile')
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda y, _: '{:g}'.format(y)))

    plt.savefig(RESULT_DIR /'pp_referrence_frequency_boxplot.png')
    plt.show()

# PP_NEW
def analyze_top(referred_pps_frequency, all_pps):
    """
    show 3 most used PPs for each category
    :param referred_pps_frequency: frequency dictionary of referred PPs
    :param all_pps: dictionary of all PP names as keys and protectionProfile objects as values
    :return: void
    """

    result = OrderedDict()
    print('*** Lists of 3 most referred PPs by technical categories ***')

    for id in referred_pps_frequency:
        category = all_pps[id].pp_csv_scan['cc_category']

        if category not in result:
            result[category] = []

        if len(result[category]) < 3:
            result[category].append(all_pps[id])

    for category in result:
        print("\nTop 3 PP in {}".format(category))
        for pp in result[category]:
            print("PP {} in file {} referred {} times; scheme {}."
                  .format(pp.pp_csv_scan['cc_pp_name'], pp.pp_filename, pp.refered_count, pp.pp_csv_scan['scheme']))

    print('\n\n')

# PP_NEW
def analyze_top_10(referred_pps_frequency, all_pps):
    """
    generate table of 10 most used PPs
    :param referred_pps_frequency: frequency dictionary of referred PPs
    :param all_pps: dictionary of all PP names as keys and protectionProfile objects as vlaues
    :return: void
    """

    top10 = {k: v for (k, v) in [x for x in referred_pps_frequency.items()][:10]}

    print('*** Lists of 10 most referred PPs ***')
    for pp_key in top10:
        pp = all_pps[pp_key]
        print("{}: PP {} in file {} referred {} times; scheme {}."
              .format(pp.pp_csv_scan['cc_category'], pp.pp_csv_scan['cc_pp_name'], pp.pp_filename, pp.refered_count, pp.pp_csv_scan['scheme']))

    print('\nLatex table:\n')
    print('\\begin{table}\n\\begin{tabularx}{\\textwidth}{ X | c | c}')
    print('\\toprule\nPP title & PP file name & referred count\\\\\n\midrule')
    for pp_key in top10:
        pp = all_pps[pp_key]
        print("{} & {} & {} \\\\"
              .format(pp.pp_csv_scan['cc_pp_name'], pp.pp_filename.replace('_', '\_'), pp.refered_count))

    print('\\end{tabularx}\n\\end{table}\n\n')

# PP_NEW
def analyze_top_10_normalized(normalized_freq_dict, all_pps):
    """
    generate table of 10 msot used PPs normalized (yearly referred)
    :param normalized_freq_dict: frequency dictionary of normalized PP usage
    :param all_pps: dictionary of all PP names as keys and protectionProfile objects as keys
    :return: void
    """

    top10 = {k: v for (k, v) in [x for x in normalized_freq_dict.items()][:10]}

    print('*** Lists of 10 most referred PPs normalized by number of years ***')
    for ref in top10:
        pp = all_pps[ref]
        print("{}: PP {} in file {} referred {} times {} refs per year; scheme {}."
              .format(pp.pp_csv_scan['cc_category'], pp.pp_csv_scan['cc_pp_name'], pp.pp_filename, pp.refered_count,
                      top10[ref], pp.pp_csv_scan['scheme']))

    print('\nLatex table:\n')
    print('\\begin{table}\n\\begin{tabularx}{\\textwidth}{ X | c | c | c}')
    print('\\toprule\nPP title & PP file name & referred & ref per year\\\\\n\midrule')
    for ref in top10:
        pp = all_pps[ref]
        print("{} & {} & {} & {} \\\\"
              .format(pp.pp_csv_scan['cc_pp_name'], pp.pp_filename.replace('_', '\_'), pp.refered_count, top10[ref]))

    print('\\end{tabularx}\n\\end{table}')

# PP_NEW
def analyze_min_references(reffered_pps_frequency, all_pps):
    """
    show PPs that are used only once
    :param reffered_pps_frequency: frequency dictionary of referred PPs
    :param all_pps: dictionary of all PP names as keys and protectionProfile objects as keys
    :return: void
    """

    print('*** List of PPs referred only once ***')
    count = 0
    for pp_key in reffered_pps_frequency:
        pp = all_pps[pp_key]
        if pp.refered_count == 1:
            count += 1
            author = []
            if pp.pp_frontpage_scan is not None:
                for header in pp.pp_frontpage_scan:
                    if TAG_PP_AUTHORS in header:
                        author.append(header[TAG_PP_AUTHORS])
                    elif TAG_DEVELOPER in header:
                        author.append(header[TAG_DEVELOPER])
            print('PP {} in file {} developed by {} referred from {} with registrator {}.'
                  .format(pp.pp_csv_scan['cc_pp_name'], pp.pp_filename, author, pp.product_csv_lines[0]['Name'], pp.product_csv_lines[0]['Manufacturer']))

    print('\nNumber of PPs referred only once: {}\n\n'.format(count))

# PP_NEW
def analyze_active_vs_archived(referred_pps_frequency, all_pps):
    """
    compute how many referred PPs are active and how many archived
    :param referred_pps_frequency: frequency dictionary of referred PPs
    :param all_pps: dictionary of all PP names as keys and protectionProfile objects as keys
    :return: void
    """
    active = 0
    archived = 0

    print('*** List of archived PPs that are referred from active CC certificates ***')
    for k in referred_pps_frequency:
        pp = all_pps[k]
        if pp.pp_csv_scan['cert_status'] == 'active':
            active += 1
        else:
            archived += 1
            print('Archived PP {} under PP reference(s) {}; {} times.'.format(pp.pp_csv_scan['cc_pp_name'], pp.pp_reference_ids, pp.refered_count))

    print('*** Number of active PPs referred from active certificates: {}'.format(active))
    print('*** Number of archived PPs referred from active certificates: {}\n\n'.format(archived))

# PP_UPDATE
def reference_frequencies_normalized_by_year(referred_pps_frequency, all_pps):
    """
    build dictionary of normalized PP usage by year
    :param referred_pps_frequency: frequency dictionary of referred PPs
    :param all_pps: dictionary of all PP names as keys and protectionProfile objects as keys
    :return: frequency dictionary of normalized PP usage by num of years active
    """

    print('*** PP reference frequencies normalized to number of years being certified ***')

    current_year = datetime.date.today().year
    normalized = {}

    for pp in referred_pps_frequency:
        date_list = all_pps[pp].pp_csv_scan['cc_certification_date'].split('/')
        ref_year = int(date_list[2])
        normalized_freq = round(all_pps[pp].refered_count / (current_year - ref_year), 2)

        normalized[pp] = normalized_freq

    normalized = {k: v for k, v in sorted(normalized.items(), reverse=True, key=lambda item: item[1])}

    print('FORMAT:\nReference: normalized frequency / frequency')
    for ref in normalized:
        print('{}: {} / {}'.format(ref, normalized[ref], all_pps[ref].refered_count))

    print('\n\n')
    return normalized

# PP_NEW
def elements_set(items):
    """
    based the PP front_page scan results show what and how many attributes are set in PP headers
    displays also TeX table
    :param items: pp_data_frontpage_all.json
    :return: void
    """

    result = {}
    total_pp = 0

    print("*** Number of properties set in PP headers ***")

    for file in items.values():

        for pp in file:

            total_pp += 1
            automated_scan = False

            if TAG_HEADER_MATCH_RULES in pp.keys():
                automated_scan = True

            for tag in pp.keys():

                if tag not in result:
                    result[tag] = [0, 0]

                if automated_scan:
                    result[tag][0] += 1
                else:
                    result[tag][1] += 1

    print("{:<23} {:<10} {:<13} {:<10}".format('Key', 'Automated scan', 'Database', 'Of'))
    for k, v in result.items():
        print("{:<30} {:<10} {:<10} {:<10}".format(k, v[0], v[1], total_pp))

    print('\nLatex table:\n')
    print('\\begin{table}\n\\begin{tabularx}{\\textwidth}{ X | c | c}')
    print('\\toprule\nKey & Automated scan & Database \\\\\n\midrule')
    for k, v in result.items():

        print("{} & {} & {} \\\\"
              .format(k, v[0], v[1]))

    print('\\end{tabularx}\n\\end{table}\n\n')

# PP_UPDATE
def registrator_barplot(pp_csv_data):
    """
    print barplot of number of PPs by the registrator country
    :param pp_csv_data: json from pp_data_complete.json results
    :return: void
    """

    active = [v['csv_scan']['scheme'] for (k, v) in pp_csv_data.items() if v['csv_scan']['cert_status'] == 'active']
    archived = [v['csv_scan']['scheme'] for (k, v) in pp_csv_data.items() if v['csv_scan']['cert_status'] == 'archived']
    active_dict = {}
    archive_dict = {}

    for pp in active:
        if pp not in active_dict:
            active_dict[pp] = 0
            archive_dict[pp] = 0
        active_dict[pp] += 1

    for pp in archived:
        if pp not in archive_dict:
            archive_dict[pp] = 0
            active_dict[pp] = 0
        archive_dict[pp] += 1

    x = np.arange(len(active_dict.keys()))
    width = 0.4

    fig, ax = plt.subplots()
    rects1 = ax.bar(x - width / 2, active_dict.values(), width, label='active', color='olivedrab')
    rects2 = ax.bar(x + width / 2, archive_dict.values(), width, label='archived', color='coral')

    ax.set_ylabel('Number of PPs.')
    ax.set_title('Number of certified PPs by the registration country.')
    ax.set_xticks(x)
    ax.set_xticklabels(active_dict.keys())
    ax.legend()

    def autolabel(rects):
        for rect in rects:
            height = rect.get_height()
            ax.annotate('{}'.format(height),
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 2),
                        textcoords="offset points",
                        ha='center', va='bottom')

    autolabel(rects1)
    autolabel(rects2)
    fig.tight_layout()
    plt.savefig(RESULT_DIR / 'registrator_bar.png')
    plt.show()

    #print(len(active))

# PP_UPDATE
def print_data_barplot(data):
    """
    print barplot based on some dictionary (for development)
    :param data: dictionary to be displayed
    :return: void
    """
    names = list(data.keys())
    values = list(data.values())

    # tick_label does the some work as plt.xticks()
    plt.bar(range(len(data)), values, width=0.6, tick_label=names)
    plt.xticks(rotation=90)
    #plt.savefig('bar.png') #TODO set as parameter of function
    plt.show()

# PP_NEW
def pp_per_file(items):
    """
    show the frequency of number of PP headers per one file
    :param items: json from pp_data_frontpage_all.json
    :return: void
    """
    counts = {}
    print('*** Files where we detect more then one PP header ***')
    for k, v in items.items():
        num_of_headers = len(v)
        if num_of_headers in counts:
            counts[num_of_headers] += 1
        else:
            counts[num_of_headers] = 1
        if num_of_headers > 1:
            print(k)

    print("\n*** Number of different PPs per document ***")
    for num_of_headers in counts:
        print('Number of PPs with {} header(s): {}'.format(num_of_headers, counts[num_of_headers]))

    print('\n\n')

# PP_NEW
def get_date_dict(items):
    """
    build frequency dictionary of PP release dates (years)
    :param items: data read form pp_data_frontpage_all.json
    :return: frequency dictionary
    """
    counts = {}
    for file in items.values():
        for pp in file:
            if TAG_PP_DATE in pp:
                tmp = re.search('\d{4}', pp[TAG_PP_DATE])
                if tmp is not None:
                    tmp = tmp.group(0)
                    if tmp in counts:
                        counts[tmp] += 1
                    else:
                        counts[tmp] = 1

    sorted_dates = dict(sorted(counts.items()))
    print(sorted_dates)
    return sorted_dates

# PP_NEW
def show_ids(pp_data, registrator, tag):
    """
    print PP ids gathered by frontpage scan (for development)
    :param pp_data:
    :param registrator: vlaue of a registrator eg. 'BSI' or 'ANSSI'
    :param tag: tag of property from tags_constants
    :return: void
    """

    count = 0
    total = 0

    for pp_file in pp_data:
        for pp in pp_data[pp_file]:
            if tag in pp:
                if TAG_PP_REGISTRATOR_SIMPLIFIED in pp and pp[TAG_PP_REGISTRATOR_SIMPLIFIED] == registrator:
                    count += 1
                total += 1

    print('{} elements set in headers of registrator {} out of {} elements set in all headers'.format(count,
                                                                                                      registrator,
                                                                                                      total))

# PP_NEW
def show_file_name(pp_data, registrator):
    """
    show PP filenames of particular registrator (for development)
    :param pp_data: data read from pp_data_frontpage_all.json
    :param registrator: registrator tag (key)
    :return: void
    """

    for pp_file in pp_data:
        if registrator == pp_data[pp_file][0][TAG_PP_REGISTRATOR_SIMPLIFIED]:
            print(pp_file)

# PP_NEW
def create_statistics():
    print('\n\n*******************************')
    print('Running statistics module')
    print('*******************************\n')
    items = read_json_results(RESULT_DIR / 'pp_data_frontpage_all.json')
    items_all = read_json_results(RESULT_DIR / 'pp_data_complete.json')
    mapping = pp_read_mapping()

    elements_set(items)

    registrator_barplot(items_all)

    cc_csv_data = read_active_product_csv()

    pp_per_file(items)

    all_pps, referred_pps = build_complex_refferences(items_all, cc_csv_data, mapping)
    refered_pps_frequency = get_refered_pps_frequency(referred_pps)

    basic_characteristics(refered_pps_frequency)
    reference_boxplot(refered_pps_frequency)
    reference_hist(refered_pps_frequency)

    analyze_min_references(refered_pps_frequency, all_pps)
    analyze_active_vs_archived(refered_pps_frequency, all_pps)
    analyze_top(refered_pps_frequency, all_pps)
    analyze_top_10(refered_pps_frequency, all_pps)
    normalized = reference_frequencies_normalized_by_year(refered_pps_frequency, all_pps)
    analyze_top_10_normalized(normalized, all_pps)

    #analyze_certificates.analyze_security_functional_component_frequency(items_all, '')
    #analyze_certificates.analyze_security_assurance_component_frequency(items_all, '')
    

if __name__ == "__main__":

    if '-h' in sys.argv or '--help' in sys.argv:

        print('Usage: python3 {} [-h | --help]'.format(sys.argv[0]))
        print('\nOptions:\n'
              '\t-h or --help\tdisplay help')
        exit(0)

    create_statistics()
