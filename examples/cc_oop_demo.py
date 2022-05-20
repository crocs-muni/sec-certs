import logging
from datetime import datetime

from sec_certs.config.configuration import config
from sec_certs.dataset.common_criteria import CCDataset

logger = logging.getLogger(__name__)


def main():
    file_handler = logging.FileHandler(config.log_filepath)
    stream_handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)
    logging.basicConfig(level=logging.INFO, handlers=[file_handler, stream_handler])
    start = datetime.now()

    # Full processing pipeline of Common Criteria dataset
    dset = CCDataset()
    dset.get_certs_from_web()
    dset.process_protection_profiles()
    dset.download_all_pdfs()
    dset.convert_all_pdfs()
    dset.analyze_certificates()  # calls dset._extract_data() and dset._compute_heuristics()

    # Other useful API below

    # explicitly dump to json
    # dset.to_json(dset.json_path)

    # Load dataset from JSON
    # new_dset = CCDataset.from_json("./debug_dataset/cc_full_dataset.json")
    # assert dset == new_dset

    # transform to pandas DataFrame
    # df = dset.to_pandas()

    end = datetime.now()
    logger.info(f"The computation took {(end-start)} seconds.")


if __name__ == "__main__":
    main()
