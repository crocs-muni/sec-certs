from extract_certificates import *
from analyze_certificates import *

import os
import json


def do_all_analysis(all_cert_items, filter_label):
    analyze_cert_years_frequency(all_cert_items, filter_label)
    analyze_references_graph(['rules_cert_id'], all_cert_items, filter_label)
    analyze_eal_frequency(all_cert_items, filter_label)
    analyze_sars_frequency(all_cert_items, filter_label)
    generate_dot_graphs(all_cert_items, filter_label)
    plot_certid_to_item_graph(['keywords_scan', 'rules_protection_profiles'], all_cert_items, filter_label, 'certid_pp_graph.dot', False)


def do_analysis_everything(all_cert_items, current_dir):
    os.chdir(current_dir + '\\..\\results\\')
    do_all_analysis(all_cert_items, '')


def do_analysis_09_01_2019_archival(all_cert_items, current_dir):
    os.chdir(current_dir + '\\..\\results\\results_archived01092019_only\\')
    archived_date = '09/01/2019'
    limited_cert_items = {x: all_cert_items[x] for x in all_cert_items if is_in_dict(all_cert_items[x], ['csv_scan', 'cc_archived_date']) and all_cert_items[x]['csv_scan']['cc_archived_date'] == archived_date}
    do_all_analysis(limited_cert_items, 'cc_archived_date={}'.format(archived_date))


def do_analysis_only_smartcards(all_cert_items, current_dir):
    os.chdir(current_dir + '\\..\\results\\results_sc_only\\')
    sc_category = 'ICs, Smart Cards and Smart Card-Related Devices and Systems'
    sc_cert_items = {x: all_cert_items[x] for x in all_cert_items if is_in_dict(all_cert_items[x], ['csv_scan', 'cc_category']) and all_cert_items[x]['csv_scan']['cc_category'] == sc_category}
    print(len(sc_cert_items))
    do_all_analysis(sc_cert_items, 'sc_category={}'.format(sc_category))


def main():
    # change current directory to store results into results file
    current_dir = os.getcwd()
    os.chdir(current_dir + '\\..\\results\\')

    cc_html_files_dir = 'c:\\Certs\\web\\'

    walk_dir = 'c:\\Certs\\cc_certs_20191208\\cc_certs\\'
    pp_dir = 'c:\\Certs\\cc_certs_20191208\\cc_pp\\'
    #pp_dir = 'c:\\Certs\\cc_certs_20191208\\cc_pp_test3\\'
    walk_dir_pp = 'c:\\Certs\\pp_20191213\\'

    #walk_dir = 'c:\\Certs\\cc_certs_test1\\'
    fragments_dir = 'c:\\Certs\\cc_certs_20191208\\cc_certs_txt_fragments\\'
    pp_fragments_dir = 'c:\\Certs\\cc_certs_20191208\\cc_pp_txt_fragments\\'

    generate_basic_download_script()

    # all_pp_csv = extract_protectionprofiles_csv(cc_html_files_dir)
    # all_pp_keywords = extract_certificates_keywords(pp_dir, pp_fragments_dir, 'pp')
    # check_expected_pp_results({}, all_pp_csv, {}, all_pp_keywords)
    # all_pp_items = collate_certificates_data({}, all_pp_csv, {}, all_pp_keywords, 'link_pp_document')
    # with open("pp_data_complete.json", "w") as write_file:
    #     write_file.write(json.dumps(all_pp_items, indent=4, sort_keys=True))

    do_extraction = False
    do_extraction_pp = False
    do_pairing = False
    do_processing = False
    do_analysis = True

    #all_pp_front = extract_protectionprofiles_frontpage(pp_dir)
    #return
    all_pdf_meta = extract_certificates_pdfmeta(walk_dir, 'certificate')

    if do_extraction:
        all_csv = extract_certificates_csv(cc_html_files_dir)
        all_html = extract_certificates_html(cc_html_files_dir)
        all_front = extract_certificates_frontpage(walk_dir)
        all_keywords = extract_certificates_keywords(walk_dir, fragments_dir, 'certificate')
        all_pdf_meta = extract_certificates_pdfmeta(walk_dir, 'certificate')

    if do_extraction_pp:
        all_pp_csv = extract_protectionprofiles_csv(cc_html_files_dir)
        all_pp_front = extract_protectionprofiles_frontpage(pp_dir)
        all_pp_keywords = extract_certificates_keywords(pp_dir, pp_fragments_dir, 'pp')

    if do_pairing:
        with open('pp_data_csv_all.json') as json_file:
            all_pp_csv = json.load(json_file)
        # with open('pp_data_html_all.json') as json_file:
        #     all_pp_html = json.load(json_file)
        # with open('v_data_frontpage_all.json') as json_file:
        #     all_pp_front = json.load(json_file)
        with open('pp_data_keywords_all.json') as json_file:
            all_pp_keywords = json.load(json_file)

        check_expected_pp_results({}, all_pp_csv, {}, all_pp_keywords)
        all_pp_items = collate_certificates_data({}, all_pp_csv, {}, all_pp_keywords, 'link_pp_document')
        with open("pp_data_complete.json", "w") as write_file:
            write_file.write(json.dumps(all_pp_items, indent=4, sort_keys=True))

        with open('certificate_data_csv_all.json') as json_file:
            all_csv = json.load(json_file)
        with open('certificate_data_html_all.json') as json_file:
            all_html = json.load(json_file)
        with open('certificate_data_frontpage_all.json') as json_file:
            all_front = json.load(json_file)
        with open('certificate_data_keywords_all.json') as json_file:
            all_keywords = json.load(json_file)

        check_expected_cert_results(all_html, all_csv, all_front, all_keywords)
        all_cert_items = collate_certificates_data(all_html, all_csv, all_front, all_keywords, 'link_security_target')
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

        with open("certificate_data_complete_processed_analyzed.json", "w") as write_file:
            write_file.write(json.dumps(all_cert_items, indent=4, sort_keys=True))

        with open('pp_data_complete.json') as json_file:
            all_pp_items = json.load(json_file)


    # TODO
    # extract pdf file metadata (pdf header, file size...), PyPDF2 https://www.blog.pythonlibrary.org/2018/04/10/extracting-pdf-metadata-and-text-with-python/, https://github.com/pdfminer/pdfminer.six
    #   https://pythonhosted.org/PyPDF2/PdfFileReader.html
    # add extraction of frontpage for protection profiles
    # If None == protection profile => Match PP with its assurance level and recompute
    #         analyze_sept2019_cleaning(all_cert_items)
    # extract info about protection profiles, download and parse pdf, map to referencing files
    # analysis of PP only: which PP is the most popular?, what schemes/countries are doing most...
    # analysis of certificates in time (per year) (different schemes)
    # how many certificates are extended? How many times
    # analysis of use of protection profiles
    # analysis of security targets documents
    # analysis of big cert clusters
    # improve logging (info, warnings, errors, final summary)
    # other schemes: FIPS140-2 certs, EMVCo, Visa Certification, American Express Certification, MasterCard Certification
    # download and analyse CC documentation
    # solve treatment of unicode characters
    # anayze bbliography
    # histogram/time of cert labs (maybe first two words heuristics)
    # Statistics about number of characters (length), words, pages
    # extract frontpage also from other than anssi and bsi certificates (US, BE...)

if __name__ == "__main__":
    main()
