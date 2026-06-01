from importlib.resources import as_file, files

import pytest
import tests.data.eucc.dataset

from sec_certs.dataset.eucc import EUCCDataset


@pytest.fixture(scope="module")
def downloaded_toy_dataset(tmp_path_factory):
    with as_file(files(tests.data.eucc.dataset) / "toy_dataset.json") as path:
        dataset = EUCCDataset.from_json(path)

    temp_dir = tmp_path_factory.mktemp("downloaded_dataset")
    dataset.copy_dataset(temp_dir)
    dataset.download_all_artifacts()

    for cert in dataset:
        for doc_type in ["cert", "st", "report"]:
            link = getattr(cert, f"{doc_type}_link")
            doc_state = getattr(cert.state, doc_type)
            if link and not doc_state.download_ok:
                pytest.skip(reason="Skip due to error during download")

    return dataset


def test_downloaded_source_hashes(downloaded_toy_dataset: EUCCDataset):
    template_report_source_hashes = {
        "e2a88386bd8e37a6": "421d0abbdab50f2e38761e990a6e8d3e9901bd1ac148ad45b0c9b3ae5edc649e",
        "68db933fd58bd56e": "0bc68c850744a7304b0139022cdc556db1e0a3b39de5551efcc374e9e9e8910b",
    }

    template_st_source_hashes = {
        "e2a88386bd8e37a6": "603eb7c8e8096bfea2964fc3fbf9cb0e5e34cfab1693dec890ee5aa2cec54526",
        "68db933fd58bd56e": "afc10ebed8238e8a8bfeed49203a7413b1cb13541b1883b23d5ddedce970f33c",
    }

    template_cert_source_hashes = {
        "e2a88386bd8e37a6": "3dff483163aa864ff84d95e150503693c111eec2b8126a19753ae3b8f0812304",
        "68db933fd58bd56e": "0d14b807e447e918d3cc290ff126dd1fc67d4eedf220f4ba2d0425aa9e8d5ac5",
    }

    for cert in downloaded_toy_dataset:
        assert cert.state.report.source_hash == template_report_source_hashes[cert.dgst]
        assert cert.state.st.source_hash == template_st_source_hashes[cert.dgst]
        assert cert.state.cert.source_hash == template_cert_source_hashes[cert.dgst]
