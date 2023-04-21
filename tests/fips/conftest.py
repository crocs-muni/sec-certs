from importlib import resources

import pytest
import tests.data.fips.dataset

from sec_certs.dataset import CPEDataset, CVEDataset, FIPSDataset


@pytest.fixture(scope="module")
def toy_dataset() -> FIPSDataset:
    with resources.path(tests.data.fips.dataset, "toy_dataset.json") as dataset_path:
        return FIPSDataset.from_json(dataset_path)


@pytest.fixture(scope="module")
def processed_dataset(
    toy_dataset: FIPSDataset, cpe_dataset: CPEDataset, cve_dataset: CVEDataset, tmp_path_factory
) -> FIPSDataset:
    tmp_dir = tmp_path_factory.mktemp("fips_dset")
    toy_dataset.copy_dataset(tmp_dir)

    tested_certs = [
        toy_dataset["3095"],
        toy_dataset["3093"],
        toy_dataset["3197"],
        toy_dataset["2441"],
    ]
    toy_dataset.certs = {x.dgst: x for x in tested_certs}

    toy_dataset.download_all_artifacts()
    toy_dataset.convert_all_pdfs()
    toy_dataset.extract_data()
    toy_dataset._compute_references(keep_unknowns=True)

    toy_dataset.auxiliary_datasets.cpe_dset = cpe_dataset
    toy_dataset.auxiliary_datasets.cve_dset = cve_dataset
    toy_dataset.compute_cpe_heuristics()
    toy_dataset.compute_related_cves()
    toy_dataset._compute_transitive_vulnerabilities()

    return toy_dataset
