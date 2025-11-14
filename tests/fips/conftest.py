from importlib.resources import as_file, files

import pytest
import tests.data.fips.dataset

from sec_certs.dataset import CPEDataset, CVEDataset, FIPSDataset
from sec_certs.dataset.auxiliary_dataset_handling import CPEDatasetHandler, CPEMatchDictHandler, CVEDatasetHandler
from sec_certs.heuristics.common import compute_cpe_heuristics, compute_related_cves, compute_transitive_vulnerabilities
from sec_certs.heuristics.fips import compute_references


@pytest.fixture(scope="module")
def toy_dataset() -> FIPSDataset:
    with as_file(files(tests.data.fips.dataset) / "toy_dataset.json") as dataset_path:
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

    cpe_handler = CPEDatasetHandler(toy_dataset.auxiliary_datasets_dir)
    cpe_handler.dset = cpe_dataset
    cve_handler = CVEDatasetHandler(toy_dataset.auxiliary_datasets_dir)
    cve_handler.dset = cve_dataset
    cpe_match_dict_handler = CPEMatchDictHandler(toy_dataset.auxiliary_datasets_dir)
    cpe_match_dict_handler.dset = {}
    toy_dataset.aux_handlers = {
        CPEDatasetHandler: cpe_handler,
        CVEDatasetHandler: cve_handler,
        CPEMatchDictHandler: cpe_match_dict_handler,
    }

    toy_dataset.download_all_artifacts()
    toy_dataset.convert_all_pdfs()
    toy_dataset.extract_data()

    compute_cpe_heuristics(toy_dataset.aux_handlers[CPEDatasetHandler].dset, toy_dataset.certs.values())
    compute_related_cves(
        toy_dataset.aux_handlers[CPEDatasetHandler].dset,
        toy_dataset.aux_handlers[CVEDatasetHandler].dset,
        toy_dataset.aux_handlers[CPEMatchDictHandler].dset,
        toy_dataset.certs.values(),
    )
    compute_references(toy_dataset.certs, keep_unknowns=True)
    compute_transitive_vulnerabilities(toy_dataset.certs)

    return toy_dataset
