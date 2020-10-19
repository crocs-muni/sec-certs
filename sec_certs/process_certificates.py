#!/usr/bin/env python3
import os
import json
from pathlib import Path

import click

from extract_certificates import *
from analyze_certificates import *


def do_all_analysis(all_cert_items, filter_label):
    generate_dot_graphs(all_cert_items, filter_label)
    analyze_cert_years_frequency(all_cert_items, filter_label)
    analyze_references_graph(['rules_cert_id'], all_cert_items, filter_label)
    analyze_eal_frequency(all_cert_items, filter_label)
    analyze_security_assurance_component_frequency(all_cert_items, filter_label)
    analyze_security_functional_component_frequency(all_cert_items, filter_label)
    analyze_pdfmeta(all_cert_items, filter_label)
    plot_certid_to_item_graph(['keywords_scan', 'rules_protection_profiles'], all_cert_items, filter_label, 'certid_pp_graph.dot', False)


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

    cert_items = {}
    for cert_item_key in all_cert_items.keys():
        item = get_item_from_dict(all_cert_items[cert_item_key], filter_path)
        if item is not None:
            if item == filter_value:
                # Match found, include
                cert_items[cert_item_key] = all_cert_items[cert_item_key]

    #cert_items = {x: all_cert_items[x] for x in all_cert_items if is_in_dict(all_cert_items[x], ['csv_scan', filter_key]) and all_cert_items[x]['csv_scan'][filter_key] == filter_value}

    print(len(cert_items))
    do_all_analysis(cert_items, '{}={}'.format(filter_string, filter_value))


def do_analysis_only_category(all_cert_items, current_dir: Path, category):
    do_analysis_only_filtered(all_cert_items, current_dir, ['csv_scan', 'cc_category'], category)


def do_analysis_only_smartcards(all_cert_items, current_dir: Path):
    do_analysis_only_category(all_cert_items, current_dir, 'ICs, Smart Cards and Smart Card-Related Devices and Systems')


def do_analysis_only_operatingsystems(all_cert_items, current_dir: Path):
    do_analysis_only_category(all_cert_items, current_dir, 'Operating Systems')


def load_json_files(files_list):
    loaded_jsons = []
    for file_name in files_list:
        with open(file_name) as json_file:
            loaded_items = json.load(json_file)
            loaded_jsons.append(loaded_items)
            print('{} loaded, total items = {}'.format(file_name, len(loaded_items)))
    return tuple(loaded_jsons)


@click.command()
@click.argument("directory", required=True, type=str)
@click.option("--fresh", "do_complete_extraction", is_flag=True, help="Whether to extract from a fresh state.")
@click.option("--do-download", "do_download_certs", is_flag=True, help="Whether to download certificate pages.")
@click.option("--do-extraction", "do_extraction", is_flag=True, help="Whether to extract information from the certs.")
@click.option("--do-pairing", "do_pairing", is_flag=True, help="Whether to pair PP stuff.")
@click.option("--do-processing", "do_processing", is_flag=True, help="Whether to process certificates.")
@click.option("--do-anaysis", "do_analysis", is_flag=True, help="Whether to analyse certificates.")
def main(directory, do_complete_extraction: bool, do_download_certs: bool, do_extraction: bool, do_pairing: bool, do_processing: bool, do_analysis: bool):
    directory = Path(directory)

    web_dir = directory / "web"
    walk_dir = directory / "certs"
    pp_dir = directory / "pp"
    fragments_dir = directory / "cert_fragments"
    pp_fragments_dir = directory / "pp_fragments"
    results_dir = directory / "results"

    web_dir.mkdir(parents=True, exist_ok=True)
    walk_dir.mkdir(parents=True, exist_ok=True)
    pp_dir.mkdir(parents=True, exist_ok=True)
    fragments_dir.mkdir(parents=True, exist_ok=True)
    pp_fragments_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    # 1. generate_basic_download_script
    # 2. run and download basic cc files from webpage (no certs yet)

    #
    # Start processing
    #
    generate_basic_download_script(web_dir)
    generate_failed_download_script(walk_dir)

    #do_complete_extraction = True
    #do_download_certs = True
    #do_extraction = True
    #do_pairing = True
    #do_processing = True
    #do_analysis = True
    do_analysis_filtered = False

    if do_complete_extraction:
        # analyze all files from scratch, set 'previous' state to empty dict
        prev_csv = {}
        prev_html = {}
        prev_front = {}
        prev_keywords = {}
        prev_pdf_meta = {}
    else:
        # load previously analyzed results
        prev_csv, prev_html, prev_front, prev_keywords, prev_pdf_meta = load_json_files(
            map(lambda x: results_dir / x, ['certificate_data_csv_all.json', 'certificate_data_html_all.json', 'certificate_data_frontpage_all.json',
             'certificate_data_keywords_all.json', 'certificate_data_pdfmeta_all.json']))

    if do_download_certs:
        # extract_certificates_html() will generate download scripts for cert documents
        # NOTE: download scripts must be run manually now
        current_html = extract_certificates_html(web_dir)

        # NOTE: Code below is preparation for differetian download of only new certificates
        # - unfinished now
        # print('*** Items: {} vs. {}'.format(len(current_html.keys()), len(prev_html.keys())))
        # current_html_keys = sorted(current_html.keys())
        # prev_html_keys = sorted(prev_html.keys())
        # new_items = list(set(current_html.keys()) - set(prev_html.keys()))
        # print('*** New items detected: {}'.format(len(new_items)))
        #
        # # find new items which are not yet processed based on the value of raw csv line
        # new_items = []
        # for current_item_key in current_csv.keys():
        #     current_item = current_csv[current_item_key]
        #     current_raw_csv = current_item['csv_scan']['raw_csv_line']
        #     match_found = False
        #     for prev_item_key in prev_csv.keys():
        #         prev_item = prev_csv[prev_item_key]
        #         prev_raw_csv = prev_item['csv_scan']['raw_csv_line']
        #         if current_raw_csv == prev_raw_csv:
        #             match_found = True
        #             break
        #     if not match_found:
        #         # we found new item
        #         new_items.append(current_item_key)
        #
        # print('*** New items detected: {}'.format(len(new_items)))

    if do_extraction:
        all_csv = extract_certificates_csv(web_dir)
        all_html = extract_certificates_html(web_dir)
        all_front = extract_certificates_frontpage(walk_dir)
        all_keywords = extract_certificates_keywords(walk_dir, fragments_dir, 'certificate')
        all_pdf_meta = extract_certificates_pdfmeta(walk_dir, 'certificate', results_dir)

        # save joined results
        with open(results_dir / "certificate_data_csv_all.json", "w") as write_file:
            json.dump(all_csv, write_file, indent=4, sort_keys=True)
        with open(results_dir / "certificate_data_html_all.json", "w") as write_file:
            json.dump(all_html,  write_file, indent=4, sort_keys=True)
        with open(results_dir / "certificate_data_frontpage_all.json", "w") as write_file:
            json.dump(all_front,  write_file, indent=4, sort_keys=True)
        with open(results_dir / "certificate_data_keywords_all.json", "w") as write_file:
            json.dump(all_keywords,  write_file, indent=4, sort_keys=True)
        with open(results_dir / "certificate_data_pdfmeta_all.json", "w") as write_file:
            json.dump(all_pdf_meta,  write_file, indent=4, sort_keys=True)

    # if do_extraction_pp:
    #     all_pp_csv = extract_protectionprofiles_csv(web_dir)
    #     all_pp_front = extract_protectionprofiles_frontpage(pp_dir)
    #     all_pp_keywords = extract_certificates_keywords(pp_dir, pp_fragments_dir, 'pp')
    #    all_pp_pdf_meta = extract_certificates_pdfmeta(pp_dir, 'pp')
    #
    #     # save joined results
    #     with open("pp_data_csv_all.json", "w") as write_file:
    #         write_file.write(json.dumps(all_pp_csv, indent=4, sort_keys=True))
    #     with open("pp_data_frontpage_all.json", "w") as write_file:
    #         write_file.write(json.dumps(all_pp_front, indent=4, sort_keys=True))
    #     with open("pp_data_keywords_all.json", "w") as write_file:
    #         write_file.write(json.dumps(all_pp_keywords, indent=4, sort_keys=True))
    #     with open("pp_data_pdfmeta_all.json", "w") as write_file:
    #         write_file.write(json.dumps(all_pp_pdf_meta, indent=4, sort_keys=True))

    if do_pairing:
        # # PROTECTION PROFILES
        # # load results from previous step
        # all_pp_csv, all_pp_front, all_pp_keywords, all_pp_pdf_meta = load_json_files(
        #     ['pp_data_csv_all.json', 'pp_data_frontpage_all.json',
        #      'pp_data_keywords_all.json', 'pp_data_pdfmeta_all.json'])
        # # check for unexpected results
        # check_expected_pp_results({}, all_pp_csv, {}, all_pp_keywords)
        # # collate all results into single file
        # all_pp_items = collate_certificates_data({}, all_pp_csv, all_pp_front, all_pp_keywords, all_pp_pdf_meta, 'link_pp_document')
        # # write collated result
        # with open("pp_data_complete.json", "w") as write_file:
        #     write_file.write(json.dumps(all_pp_items, indent=4, sort_keys=True))

        # CERTIFICATES
        # load results from previous step
        all_csv, all_html, all_front, all_keywords, all_pdf_meta = load_json_files(
            map(lambda x: results_dir / x, ['certificate_data_csv_all.json', 'certificate_data_html_all.json', 'certificate_data_frontpage_all.json',
             'certificate_data_keywords_all.json', 'certificate_data_pdfmeta_all.json']))
        # check for unexpected results
        check_expected_cert_results(all_html, all_csv, all_front, all_keywords, all_pdf_meta)
        # collate all results into single file
        all_cert_items = collate_certificates_data(all_html, all_csv, all_front, all_keywords, all_pdf_meta, 'link_security_target')

        # write collated result
        with open(results_dir / "certificate_data_complete.json", "w") as write_file:
            json.dump(all_cert_items, write_file, indent=4, sort_keys=True)

    if do_processing:
        # load information about protection profiles as extracted by sec-certs-pp tool
        with open(results_dir / 'pp_data_complete_processed.json') as json_file:
            all_pp_items = json.load(json_file)

        with open(results_dir / 'certificate_data_complete.json') as json_file:
            all_cert_items = json.load(json_file)

        all_cert_items = process_certificates_data(all_cert_items, all_pp_items)

        with open(results_dir / "certificate_data_complete_processed.json", "w") as write_file:
            json.dump(all_cert_items, write_file, indent=4, sort_keys=True)

    if do_analysis:
        with open(results_dir / 'certificate_data_complete_processed.json') as json_file:
            all_cert_items = json.load(json_file)

        if do_analysis_filtered:
            # analyze only smartcards
            do_analysis_only_filtered(all_cert_items, results_dir,
                                      ['csv_scan', 'cc_category'], 'ICs, Smart Cards and Smart Card-Related Devices and Systems')
            # analyze only operating systems
            do_analysis_only_filtered(all_cert_items, results_dir,
                                      ['csv_scan', 'cc_category'], 'Operating Systems')

            # analyze separate manufacturers
            do_analysis_manufacturers(all_cert_items, results_dir)

            # archived on 09/01/2019
            do_analysis_09_01_2019_archival(all_cert_items, results_dir)

        # analyze all certificates together
        do_analysis_everything(all_cert_items, results_dir)

        with open(results_dir / "certificate_data_complete_processed_analyzed.json", "w") as write_file:
            json.dump(all_cert_items, write_file, indent=4, sort_keys=True)


if __name__ == "__main__":
    main()


    # TODO
    # add saving of logs into file
    # include parsing from protection profiles repo
    # add differential partial download of new files only + processing + combine
      # generate download script only for new files (need to have previous version of files stored)
      # option for extraction of info just for single file?
      # allow for late extraction of keywords (only newly added regexes)
      # extraction of keywords done with the provided cert_rules_dict => cert_rules.py and cert_rules_new.py
      # detect archival of certificates
    # add tests - few selected files
    # add detection of overly long regex matches
    # add analysis of target CC version
    # extract even more pdf file metadata https://github.com/pdfminer/pdfminer.six
    # protection profiles dependency graph similarly as certid dependency graph is done
    # If None == protection profile => Match PP with its assurance level and recompute
    # extract info about protection profiles, download and parse pdf, map to referencing files
    # analysis of PP only: which PP is the most popular?, what schemes/countries are doing most...
    # analysis of certificates in time (per year) (different schemes)
    # how many certificates are extended? How many times
    # analysis of use of protection profiles
    # analysis of security targets documents
    # analysis of big cert clusters
    # improve logging (info, warnings, errors, final summary)
      # save as json, named segments (start_segment('name'), end_segment('name'), print('log_line', level)
    # other schemes: FIPS140-2 certs, EMVCo, Visa Certification, American Express Certification, MasterCard Certification
    # download and analyse CC documentation
    # solve treatment of unicode characters
    # analyze bibliography
    # Statistics about number of characters (length), words, pages - histogram of pdf length & extracted text length
    # add keywords extraction for trademarks (e.g, from 0963V2b_pdf.pdf)
    # FRONTPAGE
      # extract frontpage also from other than anssi and bsi certificates (US, BE...)
      # add extraction of frontpage for protection profiles
    # PORTABILITY
      # check functionality on Linux (script %%20 expansions..., \\ vs. /)
    # Add processing of docx files
    # search for ATR, Response APDU, and custom commands specifying the IC type (CPLC + others)
      # e.g., KECS-CR-15-105 XSmart e-Passport V1.4 EAC with SAC on M7892(eng).txt
    # use pdf2text -raw switch to preserve better tables (needs to be checked wrt existing regexes)
    # add tool for language detection, and if required, use automatic translation into english (https://pypi.org/project/googletrans/)
    # analyze technical decisions: https://www.niap-ccevs.org/Documents_and_Guidance/view_tds.cfm
    # extract names of IC (or other devices) from certificates => results in the list of certified chips in smartcards etc.
    # analyze SARs and SFRs in correlation with specific company (what level of SAR/SFR can company achieve?)
