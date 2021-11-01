from pathlib import Path
from datetime import datetime
import logging

from sec_certs.dataset.common_criteria import CCDataset
from sec_certs.config.configuration import config

logger = logging.getLogger(__name__)


def main():
    file_handler = logging.FileHandler(config.log_filepath)
    stream_handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)
    logging.basicConfig(level=logging.INFO, handlers=[file_handler, stream_handler])
    start = datetime.now()

    # Create empty dataset
    dset = CCDataset({}, Path('./debug_dataset'), 'cc_full_dataset', 'sample dataset description')

    # Load metadata for certificates from CSV and HTML sources
    dset.get_certs_from_web(to_download=True)

    # explicitly dump to json
    dset.to_json(dset.json_path)

    # Retrieve protection profile IDs
    dset.process_protection_profiles()

    # Load dataset from JSON
    new_dset = CCDataset.from_json('./debug_dataset/cc_full_dataset.json')
    assert dset == new_dset

    # Download pdfs and update json
    dset.download_all_pdfs()

    # Convert pdfs to text and update json
    dset.convert_all_pdfs()

    # Extract data from txt files and update json
    dset._extract_data()

    # transform to pandas DataFrame
    df = dset.to_pandas()

    # Compute heuristics on the dataset
    dset._compute_heuristics()

    # Compute related cves
    # dset.compute_related_cves()

    end = datetime.now()
    logger.info(f'The computation took {(end-start)} seconds.')


if __name__ == '__main__':
    main()
