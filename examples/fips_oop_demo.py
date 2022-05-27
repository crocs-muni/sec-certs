import logging
from datetime import datetime

from sec_certs.config.configuration import config
from sec_certs.dataset import FIPSDataset

logger = logging.getLogger(__name__)


def main():
    file_handler = logging.FileHandler(config.log_filepath)
    stream_handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)
    logging.basicConfig(level=logging.INFO, handlers=[file_handler, stream_handler])
    start = datetime.now()

    # Full processing of FIPS dataset, fresh run
    dset = FIPSDataset()
    dset.get_certs_from_web()
    dset.convert_all_pdfs()
    dset.pdf_scan()
    dset.extract_certs_from_tables()
    dset.finalize_results()

    # TODO: Resolve https://github.com/crocs-muni/sec-certs/issues/210 and refactor this
    # if not no_download_algs:
    #     aset.get_certs_from_web()
    #     logger.info(f"Finished parsing. Have algorithm dataset with {len(aset)} algorithm numbers.")
    #     dset.algorithms = aset

    # TODO: Resolve https://github.com/crocs-muni/sec-certs/issues/211 and uncomment
    # dset.plot_graphs(show=False)

    end = datetime.now()
    logger.info(f"The computation took {(end - start)} seconds.")


if __name__ == "__main__":
    main()
