from sec_certs.dataset import FIPSDataset, FIPSAlgorithmDataset
from pathlib import Path
from datetime import datetime
import logging
from sec_certs.helpers import download_parallel
from sec_certs.serialization import CustomJSONEncoder, CustomJSONDecoder
import json

def main():
    logging.basicConfig(level=logging.INFO)
    start = datetime.now()

    # Create empty dataset
    dset = FIPSDataset({}, Path('./fips_dataset'), 'sample_dataset', 'sample dataset description')

    # this is for creating test dataset, usually with small number of pdfs
    # dset = FIPSDataset({}, Path('./fips_test_dataset'), 'small dataset', 'small dataset for keyword testing')

    # Load metadata for certificates from CSV and HTML sources
    dset.get_certs_from_web()

    logging.info(f'Finished parsing. Have dataset with {len(dset)} certificates.')
    # Dump dataset into JSON

    dset.to_json(dset.root_dir / 'fips_full_dataset.json')
    logging.info(f'Dataset saved to {dset.root_dir}/fips_full_dataset.json')

    logging.info("Extracting keywords now.")

    dset.convert_all_pdfs()

    dset.extract_keywords()

    logging.info(f'Finished extracting certificates for {len(dset.keywords)} items.')
    logging.info(f'Dumping keywords to {dset.root_dir}/fips_full_keywords.json')
    dset.dump_keywords()

    logging.info("Searching for tables in pdfs")

    not_decoded_files = dset.extract_certs_from_tables()

    logging.info(f"Done. Files not decoded: {not_decoded_files}")

    logging.info("Parsing algorithms")
    aset = FIPSAlgorithmDataset({}, Path('fips_dataset/web/algorithms'), 'algorithms', 'sample algs')
    aset.parse_html()

    dset.algorithms = aset

    logging.info("finalizing results.")

    dset.finalize_results()

    logging.info('dump again')
    dset.to_json(dset.root_dir / 'fips_full_dataset.json')

    dset.get_dot_graph('different_new')
    end = datetime.now()
    logging.info(f'The computation took {(end - start)} seconds.')


if __name__ == '__main__':
    main()
