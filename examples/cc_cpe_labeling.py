import logging
from datetime import datetime
from pathlib import Path

from sec_certs.config.configuration import config
from sec_certs.dataset import CCDataset
from sec_certs.model.evaluation import evaluate, get_validation_dgsts

logger = logging.getLogger(__name__)


def main():
    file_handler = logging.FileHandler(config.log_filepath)
    stream_handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)
    logging.basicConfig(level=logging.INFO, handlers=[file_handler, stream_handler])
    start = datetime.now()

    # Fetch dataset metadata from CC Website, don't download nor parse PDFS
    dset = CCDataset({}, Path("./my_debug_dataset"), "cc_full_dataset", "Full CC dataset")
    dset.get_certs_from_web(to_download=True)

    # Automatically match CPEs and CVEs
    _, cpe_dset, _ = dset.compute_cpe_heuristics()
    dset.compute_related_cves()

    # Load dataset of ground truth CPE labels
    dset.load_label_studio_labels(Path(__file__).parent.parent / "data/manual_cpe_labels/cc.json")

    # Limit dataset only to validation part
    validation_dgsts = get_validation_dgsts(
        Path(__file__).parent.parent / "data/validation_test_split/cc/validation.json"
    )
    validation_certs = [x for x in dset if x.dgst in validation_dgsts]

    # Evaluate CPE matching performance metrics (on validation set) and dump classification report into json
    y_valid = [(x.heuristics.verified_cpe_matches) for x in validation_certs]
    evaluate(validation_certs, y_valid, "./my_debug_dataset/classification_report.json", cpe_dset)

    logger.info(f"{dset.json_path} should now contain fully labeled dataset.")

    end = datetime.now()
    logger.info(f"The computation took {(end-start)} seconds.")


if __name__ == "__main__":
    main()
