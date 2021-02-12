from pathlib import Path
from datetime import datetime
import logging
import click
from sec_certs.dataset import FIPSDataset, FIPSAlgorithmDataset
from sec_certs.configuration import config

@click.command()
@click.option('--config-file', help='Path to config file')
def main(config_file):
    logging.basicConfig(level=logging.INFO)
    start = datetime.now()

    # Load config
    config.load(config_file)

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

    logging.info("Converting pdfs")
    dset.convert_all_pdfs()
    dset.to_json(dset.root_dir / 'fips_full_dataset.json')

    logging.info("Extracting keywords now.")
    dset.extract_keywords()

    logging.info(f'Finished extracting certificates for {len(dset.certs)} items.')
    logging.info("Dumping dataset again...")
    dset.to_json(dset.root_dir / 'fips_full_dataset.json')

    logging.info("Searching for tables in pdfs")

    not_decoded_files = dset.extract_certs_from_tables()

    logging.info(f"Done. Files not decoded: {not_decoded_files}")
    dset.to_json(dset.root_dir / 'fips_mentioned.json')
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
