from sec_certs.dataset import CCDataset, DatasetJSONEncoder
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
        json.dump(dset, handle, cls=DatasetJSONEncoder, indent=4)

    end = datetime.now()
    logging.info(f'The computation took {(end-start)} seconds.')


if __name__ == '__main__':
    main()
