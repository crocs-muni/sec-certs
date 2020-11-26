from sec_certs.dataset import CCDataset
from sec_certs.serialization import CustomJSONEncoder, CustomJSONDecoder
from pathlib import Path
from datetime import datetime
import logging
import json


def main():
    logging.basicConfig(level=logging.INFO)
    start = datetime.now()

    # Create empty dataset
    dset = CCDataset({}, Path('./debug_dataset'), 'sample_dataset', 'sample dataset description')

    # Load metadata for certificates from CSV and HTML sources
    dset.get_certs_from_web()
    logging.info(f'Finished parsing. Have dataset with {len(dset)} certificates.')

    # Dump dataset into JSON
    with open('./debug_dataset/cc_full_dataset.json', 'w') as handle:
        json.dump(dset, handle, cls=CustomJSONEncoder, indent=4)

    # Load dataset from JSON
    with open('./debug_dataset/cc_full_dataset.json', 'r') as handle:
        new_dset = json.load(handle, cls=CustomJSONDecoder)

    assert dset == new_dset

    # Download pdfs
    dset.download_all_pdfs()

    # Convert pdfs to text
    dset.convert_all_pdfs()

    end = datetime.now()
    logging.info(f'The computation took {(end-start)} seconds.')


if __name__ == '__main__':
    main()
