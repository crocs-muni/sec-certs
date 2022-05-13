import logging
from datetime import datetime
from pathlib import Path

from sec_certs.dataset import FIPSDataset

logger = logging.getLogger(__name__)


def main():
    logging.basicConfig(level=logging.INFO)
    start = datetime.now()

    # dset: FIPSDataset = FIPSDataset({}, Path('./my_debug_dataset'), 'sample_dataset', 'sample dataset description')
    # dset.get_certs_from_web(no_download_algorithms=True)

    dset = FIPSDataset({}, Path("../fips_dataset"), "sample_dataset", "sample dataset description")
    dset.get_certs_from_web()
    # # Label CPE and compute related vulnerabilities
    # dset.compute_cpe_heuristics()
    # dset.compute_related_cves()
    #
    # # Load dataset of ground truth CPE labels
    # dset.load_label_studio_labels(Path(__file__).parent.parent / 'data/manual_cpe_labels/fips.json')
    #
    # # Limit dataset only to validation part
    # validation_dgsts = get_validation_dgsts(Path(__file__).parent.parent / 'data/validation_test_split/fips/validation.json')
    # validation_certs = [x for x in dset if x.dgst in validation_dgsts]
    #
    # # Evaluate CPE matching performance metrics (on validation set) and dump classification report into json
    # y_valid = [x.heuristics.verified_cpe_matches for x in validation_certs]
    # evaluate(validation_certs, y_valid, './my_debug_dataset/classification_report.json')

    logger.info(f"{dset.json_path} should now contain fully labeled dataset.")

    end = datetime.now()
    logger.info(f"The computation took {(end - start)} seconds.")


if __name__ == "__main__":
    main()
