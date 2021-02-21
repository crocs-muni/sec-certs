from sec_certs.dataset import CCDataset
from sec_certs.serialization import CustomJSONEncoder, CustomJSONDecoder
import sec_certs.constants as constants
from pathlib import Path
from datetime import datetime
import logging
import json

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
    dset = CCDataset({}, Path('./debug_dataset'), 'sample_dataset', 'sample dataset description')

    # Load metadata for certificates from CSV and HTML sources
    dset.get_certs_from_web(to_download=True)

    # Dump dataset into JSON
    dset.to_json('./debug_dataset/parsed_meta.json')

    # Load dataset from JSON
    dset = CCDataset.from_json('./debug_dataset/parsed_meta.json')
    # assert dset == new_dset

    # Download pdfs
    dset.download_all_pdfs()
    dset.to_json('./debug_dataset/downloaded_pdfs.json')

    # Convert pdfs to text
    dset.convert_all_pdfs()
    dset.to_json('./debug_dataset/converted_pdfs.json')

    # Extract data from txt files
    dset.extract_data()
    dset.to_json('./debug_dataset/extracted_pdfs.json')

    end = datetime.now()
    logger.info(f'The computation took {(end-start)} seconds.')


if __name__ == '__main__':
    main()
