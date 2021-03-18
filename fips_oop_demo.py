from pathlib import Path
from datetime import datetime
import logging
import click
from sec_certs.dataset import FIPSDataset, FIPSAlgorithmDataset
from sec_certs.configuration import config

@click.command()
@click.option('--config-file', help='Path to config file')
@click.option('--json-file', help='Path to dataset json file')
@click.option('--no-download-algs', help='don\'t download algs', is_flag=True)
def main(config_file, json_file, no_download_algs):
    logging.basicConfig(level=logging.INFO)
    start = datetime.now()

    # Load config
    config.load(config_file if config_file else 'sec_certs/settings.yaml')

    # Create empty dataset
    dset = FIPSDataset({}, Path('./fips_dataset'), 'sample_dataset', 'sample dataset description')

    # this is for creating test dataset, usually with small number of pdfs
    # dset = FIPSDataset({}, Path('./fips_test_dataset'), 'small dataset', 'small dataset for keyword testing')

    # Load metadata for certificates from CSV and HTML sources
    dset.get_certs_from_web(json_file=json_file, redo=True)

    logging.info(f'Finished parsing. Have dataset with {len(dset)} certificates.')
    # Dump dataset into JSON
    dset.to_json(dset.root_dir / 'fips_full_dataset.json')
    logging.info(f'Dataset saved to {dset.root_dir}/fips_full_dataset.json')

    logging.info("Converting pdfs")
    dset.convert_all_pdfs()
    dset.to_json(dset.root_dir / 'fips_full_dataset.json')

    logging.info("Extracting keywords now.")
    dset.extract_keywords(redo=True)

    logging.info(f'Finished extracting certificates for {len(dset.certs)} items.')
    logging.info("Dumping dataset again...")
    dset.to_json(dset.root_dir / 'fips_full_dataset.json')

    logging.info("Searching for tables in pdfs")

    not_decoded_files = dset.extract_certs_from_tables()

    logging.info(f"Done. Files not decoded: {not_decoded_files}")
    dset.to_json(dset.root_dir / 'fips_mentioned.json')
    logging.info("Parsing algorithms")
    if not no_download_algs:
        aset = FIPSAlgorithmDataset({}, Path('fips_dataset/web/algorithms'), 'algorithms', 'sample algs')
        aset.get_certs_from_web()

        dset.algorithms = aset

    logging.info("finalizing results.")

    dset.finalize_results()

    logging.info('dump again')
    dset.to_json(dset.root_dir / 'fips_full_dataset.json')

    dset.get_dot_graph('different_new')

    data = dset.match_algs(show_graph=True)
    sorted_data = data.value_counts(ascending=True)

    logging.info(sorted_data.where(sorted_data > 1).dropna())

    end = datetime.now()
    logging.info(f'The computation took {(end - start)} seconds.')


if __name__ == '__main__':
    main()
