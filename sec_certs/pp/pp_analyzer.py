import sys
from pathlib import Path
from zipfile import ZipFile

import pp_matcher
import pp_process
import pp_id_generator
import json

APP_ROOT_DIR = Path('..')
SEC_CERTS_PATH = APP_ROOT_DIR / 'sec-certs-master.zip'


def main(argv):

    if '-h' in sys.argv or '--help' in sys.argv:

        print('Usage: python3 {} [-h | --help]'
              ' [--download-pps]'
              ' [--download-st-certification-reports]'
              ' [--force-id-generation]'.format(sys.argv[0]))
        print('\nOptions:\n'
              '\t-h or --help\tdisplay help\n'
              '\t--download-pps\twill also download active PPs based on active PPs CSV\n'
              '\t--download-st-certification-reports\twill also download active ST certification reprots based on active '
              'products CSV\n'
              '\t--force-id-generation\twill generate new database of IDs and override current database')
        exit(0)

    download_pps = False
    download_st_reports = False
    force_id_generation = False

    if '--download-pps' in argv:
        download_pps = True

    all_pp_items = pp_process.process_pps(download_pps)

    if '--download-st-certification-reports' in argv:
        download_st_reports = True

    pp_reference_matching, file_to_id_pp_mapping = pp_matcher.performMatching(download_st_reports)

    if '--force-id-generation' in argv:
        force_id_generation = True

    pp_id_generator.run_generator(force_id_generation)
    csvpp_to_ppid_mapping = pp_id_generator.read_pp_mapper()

    all_pp_items = pp_process.process_pp_to_id(all_pp_items, file_to_id_pp_mapping, csvpp_to_ppid_mapping)
    with open("pp_data_complete_processed.json", "w") as write_file:
        write_file.write(json.dumps(all_pp_items, indent=4, sort_keys=True))

    #TODO uncomment this to use sec-certs project
    #with ZipFile(SEC_CERTS_PATH, 'r') as zipObject:
    #    zipObject.extractall(APP_ROOT_DIR / '..')

    import pp_statistics
    
    pp_statistics.create_statistics()


if __name__ == '__main__':
    main(sys.argv)