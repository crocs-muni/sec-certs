from extract_certificates import *
from analyze_certificates import *

import os
import json


def do_all_analysis(all_cert_items, filter_label):
    analyze_cert_years_frequency(all_cert_items, filter_label)
    analyze_references_graph(['rules_cert_id'], all_cert_items, filter_label)
    analyze_eal_frequency(all_cert_items, filter_label)
    analyze_security_assurance_component_frequency(all_cert_items, filter_label)
    analyze_security_functional_component_frequency(all_cert_items, filter_label)
    analyze_pdfmeta(all_cert_items, filter_label)
    generate_dot_graphs(all_cert_items, filter_label)
    plot_certid_to_item_graph(['keywords_scan', 'rules_protection_profiles'], all_cert_items, filter_label, 'certid_pp_graph.dot', False)


def do_analysis_everything(all_cert_items, current_dir):
    target_folder = current_dir + '\\..\\results\\'
    if not os.path.exists(target_folder):
        os.makedirs(target_folder)
    os.chdir(target_folder)
    do_all_analysis(all_cert_items, '')


def do_analysis_09_01_2019_archival(all_cert_items, current_dir):
    target_folder = current_dir + '\\..\\results\\results_archived01092019_only\\'
    if not os.path.exists(target_folder):
        os.makedirs(target_folder)
    os.chdir(target_folder)
    archived_date = '09/01/2019'
    limited_cert_items = {x: all_cert_items[x] for x in all_cert_items if is_in_dict(all_cert_items[x], ['csv_scan', 'cc_archived_date']) and all_cert_items[x]['csv_scan']['cc_archived_date'] == archived_date}
    do_all_analysis(limited_cert_items, 'cc_archived_date={}'.format(archived_date))


def do_analysis_only_smartcards(all_cert_items, current_dir):
    target_folder = current_dir + '\\..\\results\\results_sc_only\\'
    if not os.path.exists(target_folder):
        os.makedirs(target_folder)
    os.chdir(target_folder)
    sc_category = 'ICs, Smart Cards and Smart Card-Related Devices and Systems'
    sc_cert_items = {x: all_cert_items[x] for x in all_cert_items if is_in_dict(all_cert_items[x], ['csv_scan', 'cc_category']) and all_cert_items[x]['csv_scan']['cc_category'] == sc_category}
    print(len(sc_cert_items))
    do_all_analysis(sc_cert_items, 'sc_category={}'.format(sc_category))


def load_json_files(files_list):
    loaded_jsons = []
    for file_name in files_list:
        with open(file_name) as json_file:
            loaded_jsons.append(json.load(json_file))
    return tuple(loaded_jsons)


def main():
    current_dir = os.getcwd()
    results_folder = '\\..\\results\\'

    # ensure existence of results folder

    if not os.path.exists(current_dir + results_folder):
        os.makedirs(current_dir + results_folder)

    # change current directory to store results into results file
    os.chdir(current_dir + results_folder)

    ### Paths for certificates downloaded on 20191208
    paths_20191208 = {}
    paths_20191208['cc_html_files_dir'] = 'c:\\Certs\\cc_certs_20191208\\web\\'
    paths_20191208['walk_dir'] = 'c:\\Certs\\cc_certs_20191208\\cc_certs\\'
    #paths_20191208['walk_dir'] = 'c:\\Certs\\cc_certs_20191208\\cc_certs_test1\\'
    paths_20191208['pp_dir'] = 'c:\\Certs\\cc_certs_20191208\\cc_pp\\'
    #paths_20191208['pp_dir'] = 'c:\\Certs\\cc_certs_20191208\\cc_pp_test1\\'
    paths_20191208['fragments_dir'] = 'c:\\Certs\\cc_certs_20191208\\cc_certs_txt_fragments\\'
    paths_20191208['pp_fragments_dir'] = 'c:\\Certs\\cc_certs_20191208\\cc_pp_txt_fragments\\'

    ### Paths for certificates downloaded on 20200225
    paths_20200225 = {}
    paths_20200225['cc_html_files_dir'] = 'c:\\Certs\\cc_certs_20200225\\web\\'
    paths_20200225['walk_dir'] = 'c:\\Certs\\cc_certs_20200225\\cc_certs\\'
    paths_20200225['pp_dir'] = 'c:\\Certs\\cc_certs_20200225\\cc_pp\\'
    paths_20200225['fragments_dir'] = 'c:\\Certs\\cc_certs_20200225\\cc_certs_txt_fragments\\'
    paths_20200225['pp_fragments_dir'] = 'c:\\Certs\\cc_certs_20200225\\cc_pp_txt_fragments\\'

    # initialize paths based on the profile used
    paths_used = paths_20191208
    #paths_used = paths_20200225

    cc_html_files_dir = paths_used['cc_html_files_dir']
    walk_dir = paths_used['walk_dir']
    pp_dir = paths_used['pp_dir']
    fragments_dir = paths_used['fragments_dir']
    pp_fragments_dir = paths_used['pp_fragments_dir']


    #
    # Start processing
    #

    generate_basic_download_script()
    generate_missing_download_script(walk_dir)

    # all_pp_csv = extract_protectionprofiles_csv(cc_html_files_dir)
    # all_pp_keywords = extract_certificates_keywords(pp_dir, pp_fragments_dir, 'pp')
    # check_expected_pp_results({}, all_pp_csv, {}, all_pp_keywords)
    # all_pp_items = collate_certificates_data({}, all_pp_csv, {}, all_pp_keywords, 'link_pp_document')
    # with open("pp_data_complete.json", "w") as write_file:
    #     write_file.write(json.dumps(all_pp_items, indent=4, sort_keys=True))

    do_complete_extraction = False
    do_extraction = True
    do_extraction_pp = False
    do_pairing = False
    do_processing = False
    do_analysis = True

    # with open('certificate_data_complete_processed.json') as json_file:
    #     all_cert_items = json.load(json_file)
    # analyze_pdfmeta(all_cert_items, '')

    #all_pp_front = extract_protectionprofiles_frontpage(pp_dir)
    #all_pdf_meta = extract_certificates_pdfmeta(walk_dir, 'certificate')
    #all_pp_pdf_meta = extract_certificates_pdfmeta(pp_dir, 'pp')
    #return

    if do_complete_extraction:
        # set 'previous' state to empty lists
        prev_csv = []
        prev_html = []
        prev_front = []
        prev_keywords = []
        prev_pdf_meta = []
    else:
        # load previously analyzed results
        prev_csv, prev_html, prev_front, prev_keywords, prev_pdf_meta = load_json_files(
            ['certificate_data_csv_all.json', 'certificate_data_html_all.json', 'certificate_data_frontpage_all.json',
             'certificate_data_keywords_all.json', 'certificate_data_pdfmeta_all.json'])

    if do_extraction:
        all_csv = extract_certificates_csv(cc_html_files_dir, False)
        all_html = extract_certificates_html(cc_html_files_dir, False)
        all_front = extract_certificates_frontpage(walk_dir, False)
        all_keywords = extract_certificates_keywords(walk_dir, fragments_dir, 'certificate', False)
        all_pdf_meta = extract_certificates_pdfmeta(walk_dir, 'certificate', False)

        with open("certificate_data_csv_all.json", "w") as write_file:
            write_file.write(json.dumps(all_csv, indent=4, sort_keys=True))
        with open("certificate_data_html_all.json", "w") as write_file:
            write_file.write(json.dumps(all_html, indent=4, sort_keys=True))
        with open("certificate_data_frontpage_all.json", "w") as write_file:
            write_file.write(json.dumps(all_front, indent=4, sort_keys=True))
        with open("certificate_data_keywords_all.json", "w") as write_file:
            write_file.write(json.dumps(all_keywords, indent=4, sort_keys=True))
        with open("certificate_data_pdfmeta_all.json", "w") as write_file:
            write_file.write(json.dumps(all_pdf_meta, indent=4, sort_keys=True))


    if do_extraction_pp:
        all_pp_csv = extract_protectionprofiles_csv(cc_html_files_dir)
        all_pp_front = extract_protectionprofiles_frontpage(pp_dir)
        all_pp_keywords = extract_certificates_keywords(pp_dir, pp_fragments_dir, 'pp')
        all_pp_pdf_meta = extract_certificates_pdfmeta(pp_dir, 'pp')



    if do_pairing:
        # PROTECTION PROFILES
        # load results from previous step
        all_pp_csv, all_pp_html, all_pp_front, all_pp_keywords, all_pp_pdf_meta = load_json_files(
            ['pp_data_csv_all.json', 'pp_data_html_all.json', 'pp_data_frontpage_all.json',
             'pp_data_keywords_all.json', 'pp_data_pdfmeta_all.json'])
        # check for unexpected results
        check_expected_pp_results({}, all_pp_csv, {}, all_pp_keywords)
        # collate all results into single file
        all_pp_items = collate_certificates_data({}, all_pp_csv, {}, all_pp_keywords, all_pp_pdf_meta, 'link_pp_document')
        # write collated result
        with open("pp_data_complete.json", "w") as write_file:
            write_file.write(json.dumps(all_pp_items, indent=4, sort_keys=True))


        # CERTIFICATES
        # load results from previous step
        all_csv, all_html, all_front, all_keywords, all_pdf_meta = load_json_files(
            ['certificate_data_csv_all.json', 'certificate_data_html_all.json', 'certificate_data_frontpage_all.json',
             'certificate_data_keywords_all.json', 'certificate_data_pdfmeta_all.json'])
        # check for unexpected results
        check_expected_cert_results(all_html, all_csv, all_front, all_keywords, all_pdf_meta)
        # collate all results into single file
        all_cert_items = collate_certificates_data(all_html, all_csv, all_front, all_keywords, all_pdf_meta, 'link_security_target')
        # write collated result
        with open("certificate_data_complete.json", "w") as write_file:
            write_file.write(json.dumps(all_cert_items, indent=4, sort_keys=True))

    if do_processing:
        with open('certificate_data_complete.json') as json_file:
            all_cert_items = json.load(json_file)
        all_pp_items = {}

        all_cert_items = process_certificates_data(all_cert_items, all_pp_items)

        with open("certificate_data_complete_processed.json", "w") as write_file:
            write_file.write(json.dumps(all_cert_items, indent=4, sort_keys=True))

    if do_analysis:
        with open('certificate_data_complete_processed.json') as json_file:
            all_cert_items = json.load(json_file)

        current_dir = os.getcwd()

        # analyze all certificates together
        do_analysis_everything(all_cert_items, current_dir)
        # archived on 09/01/2019
        do_analysis_09_01_2019_archival(all_cert_items, current_dir)
        # analyze only smartcards
        do_analysis_only_smartcards(all_cert_items, current_dir)

        os.chdir(current_dir)
        with open("certificate_data_complete_processed_analyzed.json", "w") as write_file:
            write_file.write(json.dumps(all_cert_items, indent=4, sort_keys=True))

        #with open('pp_data_complete.json') as json_file:
        #    all_pp_items = json.load(json_file)


    # TODO
    # add differential partial download of new files only + processing + combine
      # generate download script only for new files (need to have previous version of files stored)
      # option for extraction of info just for single file?
      # allow for late extraction of keywords (only newly added regexes)
      # extraction of keywords done with the provided cert_rules_dict => cert_rules.py and cert_rules_new.py
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
      # check functionality on Linux (script %%20 expansions...)
    # Add processing of docx files

if __name__ == "__main__":
    main()
