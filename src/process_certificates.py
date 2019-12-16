from extract_certificates import *
from analyze_certificates import *

import os
import json


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

    # if do_extraction_pp:
    #     all_pp_csv = extract_protectionprofiles_csv(cc_html_files_dir)
    #     all_pp_html = extract_protectionprofiles_html(cc_html_files_dir)
    #     all_pp_front = extract_protectionprofiles_frontpage(walk_dir_pp)
    #     all_pp_keywords = extract_certificates_keywords(walk_dir_pp, fragments_dir, 'pp')

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


    #         analyze_sept2019_cleaning(all_cert_items)
    # extract info about protection profiles, download and parse pdf, map to referencing files
    # analysis of PP only: which PP is the most popular?, what schemes/countries are doing most...
    # analysis of certificates in time (per year) (different schemes)
    # how many certificates are extended? How many times
    # analysis of use of protection profiles
    # analysis of security targets documents
    # analysis of big cert clusters
    # improve logging (info, warnings, errors, final summary)


if __name__ == "__main__":
    main()
