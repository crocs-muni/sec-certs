from datetime import datetime
import logging
from pathlib import Path

from sec_certs.dataset import CCDataset
import sec_certs.constants as constants

logger = logging.getLogger(__name__)


def main():
    file_handler = logging.FileHandler(constants.LOGS_FILENAME)
    stream_handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)
    logging.basicConfig(level=logging.INFO, handlers=[file_handler, stream_handler])
    start = datetime.now()

    dset = CCDataset({}, Path('./my_debug_datset'), 'cc_full_dataset', 'Full CC dataset')
    dset.get_certs_from_web(to_download=True, update_json=True)
    dset.compute_heuristics()
    dset.manually_verify_cpe_matches()

    logger.info(f'{dset.json_path} should now contain fully labeled dataset.')

    end = datetime.now()
    logger.info(f'The computation took {(end-start)} seconds.')


if __name__ == '__main__':
    main()
