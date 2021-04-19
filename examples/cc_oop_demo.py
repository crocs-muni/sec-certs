from sec_certs.dataset.common_criteria import CCDataset
from sec_certs.serialization import CustomJSONEncoder, CustomJSONDecoder
import sec_certs.constants as constants
from pathlib import Path
from datetime import datetime
import logging
import json
import pandas as pd

logger = logging.getLogger(__name__)


def main():
    file_handler = logging.FileHandler(constants.LOGS_FILENAME)
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

    # Load dataset from JSON
    new_dset = CCDataset.from_json('./debug_dataset/cc_full_dataset.json')
    assert dset == new_dset

    # Download pdfs and update json
    dset.download_all_pdfs(update_json=True)

    # Convert pdfs to text and update json
    dset.convert_all_pdfs(update_json=True)

    # Extract data from txt files and update json
    dset.extract_data(update_json=True)

    # transform to pandas DataFrame
    df = dset.to_pandas()

    # Compute heuristics on the dataset
    dset.compute_heuristics(update_json=True)

    # Manually verify CPE findings and compute related cves
    # dset.manually_verify_cpe_matches(update_json=True)
    # dset.compute_related_cves()



    end = datetime.now()
    logger.info(f'The computation took {(end-start)} seconds.')


if __name__ == '__main__':
    main()
