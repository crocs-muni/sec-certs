#!/usr/bin/env python3

import click
from sec_certs.files import load_json_files
from sec_certs.extract_certificates import *
from sec_certs.analyze_certificates import *
from sec_certs.download import download_cc_web, download_cc
from sec_certs.cert_rules import rules as cc_search_rules, rules_certidctx


@click.command()
@click.argument("directory", required=True, type=str)
@click.option("--fresh", "do_complete_extraction", is_flag=True, help="Whether to extract from a fresh state.")
@click.option("--do-download-meta", "do_download_meta", is_flag=True, help="Whether to download meta pages.")
@click.option("--do-extraction-meta", "do_extraction_meta", is_flag=True, help="Whether to extract information from the meta pages.")
@click.option("--do-download-certs", "do_download_certs", is_flag=True, help="Whether to download certs.")
@click.option("--do-pdftotext", "do_pdftotext", is_flag=True, help="Whether to perform pdftotext conversion of the certs.")
@click.option("--do-extraction", "do_extraction_certs", is_flag=True, help="Whether to extract information from the certs.")
@click.option("--do-pairing", "do_pairing", is_flag=True, help="Whether to pair PP stuff.")
@click.option("--do-processing", "do_processing", is_flag=True, help="Whether to process certificates.")
@click.option("--do-analysis", "do_analysis", is_flag=True, help="Whether to analyse certificates.")
@click.option("--do-analysis-fips", "do_analysis_fips", is_flag=True, help="Whether to analyse fips certificates.")
@click.option("--do-find-affected", "do_find_affected", help="Find affected certs.", multiple=True, type=str, metavar="certificate id")
@click.option("--do-find-affecting", "do_find_affecting", help="Find certificates affecting the provided one", multiple=True, type=str, metavar="certificate id")
@click.option("--do-find-affected-keyword", "do_find_affected_keywords", help="Find certs referencing all certs with specific keyword.", multiple=True, type=str, metavar="keyword")
@click.option("--do-analyze-cpe", "do_analyze_cpe", is_flag=True, help="Match certificates with the Common Platform Enumeration (CPE) items")
@click.option("--analysis-label", "analysis_label", help="Optional custom label for analysis results", multiple=False, type=str, metavar="custom label")
@click.option("-t", "--threads", "threads", type=int, default=4, help="Amount of threads to use.")
def main(directory, do_complete_extraction: bool, do_download_meta: bool, do_extraction_meta: bool,
         do_download_certs: bool, do_pdftotext: bool, do_extraction_certs: bool,
         do_pairing: bool, do_processing: bool, do_analysis: bool, do_analysis_fips: bool, do_find_affected: list,
         do_find_affected_keywords: list, do_find_affecting: list, do_analyze_cpe: bool, analysis_label: str, threads: int):

    directory = Path(directory)
    web_dir = directory / "web"
    walk_dir = directory / "certs"
    certs_dir = walk_dir / "certs"
    targets_dir = walk_dir / "targets"
    pp_dir = directory / "pp"
    fragments_dir = directory / "cert_fragments"
    pp_fragments_dir = directory / "pp_fragments"
    results_dir = directory / "results"

    web_dir.mkdir(parents=True, exist_ok=True)
    walk_dir.mkdir(parents=True, exist_ok=True)
    certs_dir.mkdir(parents=True, exist_ok=True)
    targets_dir.mkdir(parents=True, exist_ok=True)
    pp_dir.mkdir(parents=True, exist_ok=True)
    fragments_dir.mkdir(parents=True, exist_ok=True)
    pp_fragments_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    #
    # Start processing
    #
    do_analysis_filtered = True

    if do_complete_extraction:
        # analyze all files from scratch, set 'previous' state to empty dict
        prev_csv = {}
        prev_html = {}
        prev_download = []
        prev_front = {}
        prev_keywords = {}
        prev_pdf_meta = {}
    else:
        # load previously analyzed results
        prev_csv, prev_html, prev_download, prev_front, prev_keywords, prev_pdf_meta = load_json_files(
            map(lambda x: results_dir / x, ['certificate_data_csv_all.json',
                                            'certificate_data_html_all.json',
                                            'certificate_data_download_all.json',
                                            'certificate_data_frontpage_all.json',
                                            'certificate_data_keywords_all.json',
                                            'certificate_data_pdfmeta_all.json']))

    if do_download_meta:
        download_cc_web(web_dir, threads)

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

    if do_extraction_meta:
        all_csv = extract_certificates_csv(web_dir)
        all_html, certs, updates = extract_certificates_html(web_dir)

        with open(results_dir / "certificate_data_csv_all.json", "w") as write_file:
            json.dump(all_csv, write_file, indent=4, sort_keys=True)
        with open(results_dir / "certificate_data_html_all.json", "w") as write_file:
            json.dump(all_html, write_file, indent=4, sort_keys=True)
        with open(results_dir / "certificate_data_download_all.json", "w") as write_file:
            json.dump(certs + updates, write_file, indent=4, sort_keys=True)

    if do_download_certs:
        all_download = load_json_files([results_dir / "certificate_data_download_all.json"])
        download_cc(walk_dir, all_download[0], threads)

    if do_pdftotext:
        convert_pdf_files(walk_dir, threads, ["-raw"])


    # if True:
    #     # extract certificates references with context
    #     all_keywords = extract_certificates_keywords_parallel_certid(walk_dir, fragments_dir, 'certificate', rules_certidctx, threads)
    #     with open(results_dir / "certificate_data_keywords_certidctx.json", "w") as write_file:
    #         json.dump(all_keywords,  write_file, indent=4, sort_keys=True)
    #
    #     return

    if do_extraction_certs:
        all_keywords = extract_certificates_keywords_parallel(walk_dir, fragments_dir, 'certificate', cc_search_rules, threads)
        with open(results_dir / "certificate_data_keywords_all.json", "w") as write_file:
            json.dump(all_keywords,  write_file, indent=4, sort_keys=True)

        all_front = extract_certificates_frontpage(walk_dir)
        with open(results_dir / "certificate_data_frontpage_all.json", "w") as write_file:
            json.dump(all_front,  write_file, indent=4, sort_keys=True)

        all_pdf_meta = extract_certificates_pdfmeta_parallel(walk_dir, 'certificate', threads)
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
            map(lambda x: results_dir / x, ['certificate_data_csv_all.json',
                                            'certificate_data_html_all.json',
                                            'certificate_data_frontpage_all.json',
                                            'certificate_data_keywords_all.json',
                                            'certificate_data_pdfmeta_all.json']))
        # check for unexpected results
        check_expected_cert_results(all_html, all_csv, all_front, all_keywords, all_pdf_meta)
        # collate all results into single file
        all_cert_items = collate_certificates_data(all_html, all_csv, all_front, all_keywords, all_pdf_meta, 'link_security_target')

        # write collated result
        with open(results_dir / "certificate_data_complete.json", "w") as write_file:
            json.dump(all_cert_items, write_file, indent=4, sort_keys=True)

    if do_processing:
        # load information about protection profiles as extracted by sec-certs-pp tool
        all_pp_items = {}
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
            # plot only selected analysis up to date 2020
            do_analysis_force_end_date(all_cert_items, results_dir, 2020)

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

    # example: --do-find-affected-keyword v1\.02\.013 --analysis-label roca   # (roca library)
    # example: --do-find-affected-keyword AT90SC --do-find-affected-keyword 00\.03\.11\.05 --analysis-label minerva   # (minerva library and chip)
    # note: keyword search is as by regexes, so mind . etc.
    if len(do_find_affected_keywords) > 0:
        results_dir = results_dir \

        search_rules = {'keyword': do_find_affected_keywords}
        all_keywords = extract_certificates_keywords_parallel(walk_dir, None, 'certificate', search_rules, threads)

        # extract file names with keyword(s) match, extract cert id(s), fill do_find_affected list for further analysis
        with open(results_dir / 'certificate_data_complete_processed.json') as json_file:
            all_cert_items = json.load(json_file)

        # match search results to cert ids
        certs_with_keywords = process_matched_keywords(all_cert_items, all_keywords,
                                                       list(do_find_affected_keywords), results_dir)

        # save list of found cert ids to separate json
        name_results = get_name_for_keyword_search_results(do_find_affected_keywords)
        file_name_results = analysis_label + '_' + name_results + '.json'
        with open(results_dir / file_name_results, "w") as write_file:
            json.dump(certs_with_keywords, write_file, indent=4, sort_keys=True)

        # populate list with certs is to analyse (same as would be --do-find-affected with explicitly specified ids)
        for i in certs_with_keywords['certs'].keys():
            do_find_affected = do_find_affected + (i,)

        # set output folder according to analysis label
        out_folder = analysis_label + '_' + name_results
        results_out_dir = results_dir / out_folder

        do_analysis_affected(all_cert_items, results_out_dir, list(do_find_affected), analysis_label)

    # analysis of all certs referencing (directly/indirectly) the specified cert id(s)
    # example: --do-find-affected BSI-DSZ-CC-0782-2012
    # example: --do-find-affected BSI-DSZ-CC-0833-2013 --do-find-affected BSI-DSZ-CC-0921-2014 --analysis-label roca_ATeHealth_Atos  # (from eIDAS ID163484)
    # example: --do-find-affected BSI-DSZ-CC-0758-2012 --do-find-affected BSI-DSZ-CC-0782-2012 --analysis-label roca_ATeHealth_Inf
    if len(do_find_affected) > 0:
        with open(results_dir / 'certificate_data_complete_processed_analyzed.json') as json_file:
            all_cert_items = json.load(json_file)
        # set output folder according to analysis label
        results_out_dir = results_dir / analysis_label
        do_analysis_affected(all_cert_items, results_out_dir, list(do_find_affected), analysis_label)

    # find all certificates which are potentially affecting security of the provided one ()
    # example: --do-find-affecting ANSSI-CC-2013/55     # Estonia estID
    # example: --do-find-affecting ANSSI-CC-2020/44     # eTravel v2.2 EAC/BAC on MultiApp v4.0.1 platform with Filter Set 1.0 version 1.0
    if len(do_find_affecting) > 0:
        with open(results_dir / 'certificate_data_complete_processed_analyzed.json') as json_file:
            all_cert_items = json.load(json_file)
        # set output folder according to analysis label
        results_out_dir = results_dir / analysis_label
        do_analysis_affecting(all_cert_items, results_out_dir, list(do_find_affecting), analysis_label)

    # analysis of fips extracted data
    if do_analysis_fips:
        with open(results_dir / 'fips_full_dataset.json') as json_file:
            all_cert_items = json.load(json_file)

        # idea: transform into cc-like json then use same analysis functions
        do_analysis_fips_certs(all_cert_items, results_dir)

    # matching to CPE and analysis
    if do_analyze_cpe:
        with open(results_dir / 'certificate_data_complete_processed_analyzed.json') as json_file:
            all_cert_items = json.load(json_file)

        # load cpe items if not already
        if os.path.isfile(results_dir / 'cpe_processed.json'):
            with open(results_dir / 'cpe_processed.json') as json_file:
                all_cpe_items = json.load(json_file)
        else:
            all_cpe_items = do_extract_cpe_items(results_dir)
            print('Total CPE items found={}'.format(len(all_cpe_items)))
            with open(results_dir / "cpe_processed.json", "w") as write_file:
                json.dump(all_cpe_items, write_file, indent=4, sort_keys=True)

        if os.path.isfile(results_dir / 'cpe_to_certs.json') and os.path.isfile(results_dir / 'certs_to_cpe.json'):
            with open(results_dir / "cpe_to_certs.json") as json_file:
                cpe_to_certs = json.load(json_file)
            with open(results_dir / "certs_to_cpe.json") as json_file:
                certs_to_cpe = json.load(json_file)
        else:
            # match cpe to certificates
            #certs_to_cpe, cpe_to_certs = do_process_cpe_to_certs((all_cpe_items, all_cert_items, 1, True))
            certs_to_cpe, cpe_to_certs = do_process_cpe_to_certs_parallel2(all_cpe_items, all_cert_items, threads * 3)

            print('Total CPEs with matching certificate(s) = {}'.format(len(cpe_to_certs)))
            with open(results_dir / "cpe_to_certs.json", "w") as write_file:
                json.dump(cpe_to_certs, write_file, indent=4, sort_keys=True)
            print('Total certs with matching CPEs = {}'.format(len(certs_to_cpe)))
            with open(results_dir / "certs_to_cpe.json", "w") as write_file:
                json.dump(certs_to_cpe, write_file, indent=4, sort_keys=True)

        single_match_certs_cpe = do_analyze_cpe_certs(cpe_to_certs, certs_to_cpe, all_cpe_items, all_cert_items)
        with open(results_dir / "certs_to_cpe_single_match.json", "w") as write_file:
            json.dump(single_match_certs_cpe, write_file, indent=4, sort_keys=True)


if __name__ == "__main__":
    main()

    # separate certificates references to devices from same/different vendor (=> who is mostly using a who is mostly used)
    # add graph showing EAL level per schemes (e.g., is BSI certifying higher than Spain?)
    # add graph showing EAL levels for protection profiles in time
    # try to find same products between CC and FIPS
    # plot certs to protection profiles
    # compute vulns from certs_to_cpe_single_match.json
    # heatmap - variable in time. E.g., certificate validity time based on the date of certificate
    # add keyword_rules as json to be loadable
    # TODO
    # plot SFRs based on whole classes, not only all together
    # for SARs, filter out values required by base EAL (so consider only augmented items)
    # plot minimum required SAR levels for different EALs
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
