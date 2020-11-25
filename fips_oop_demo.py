from sec_certs.dataset import FIPSDataset
from pathlib import Path
from datetime import datetime
import logging


def main():
    logging.basicConfig(level=logging.INFO)
    start = datetime.now()

    # Create empty dataset
    dset = FIPSDataset({}, Path('./fips_dataset'), 'sample_dataset', 'sample dataset description')

    # Load metadata for certificates from CSV and HTML sources
    dset.get_certs_from_web()
    algs = dset.present_algorithms()
    print(algs)
    a = {
        'CVL', 'AES', 'DRBG', 'HMAC', 'SHS', 'Component', 'ECDSA', 'RSA', 'DSA', 'C'

    }
    # logging.info(f'Finished parsing. Have dataset with {len(dset)} certificates.')
    # # Dump dataset into JSON
    #
    # dset.dump_to_json()
    # logging.info(f'Dataset saved to {dset.root_dir}/fips_full_dataset.json')
    #
    # logging.info("Extracting keywords now.")
    #
    # dset.extract_keywords()
    #
    # logging.info(f'Finished extracting certificates for {len(dset.keywords)} items.')
    # logging.info(f'Dumping keywords to {dset.root_dir}/fips_full_keywords.json')
    # dset.dump_keywords()
    #
    # logging.info("Searching for tables in pdfs")
    #
    # # not_decoded_files = dset.extract_certs_from_tables()
    #
    # # logging.info(f"Done. Files not decoded: {not_decoded_files}")
    #
    # logging.info("finalizing results.")
    #
    # dset.finalize_results()

    end = datetime.now()
    logging.info(f'The computation took {(end - start)} seconds.')


if __name__ == '__main__':
    main()
