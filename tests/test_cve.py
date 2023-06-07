from __future__ import annotations

import itertools
from pathlib import Path

import pytest

from sec_certs.dataset import CVEDataset
from sec_certs.sample import CPE, CVE
from sec_certs.serialization.json import SerializationError


def test_cve_dset_lookup_dicts(cve_dataset: CVEDataset):
    assert cve_dataset._cpe_uri_to_cve_ids_lookup["cpe:2.3:o:linux:linux_kernel:2.4.18:*:*:*:*:*:*:*"] == {
        "CVE-2003-0001"
    }
    assert cve_dataset._cpe_uri_to_cve_ids_lookup[
        "cpe:2.3:a:ibm:security_access_manager_for_enterprise_single_sign-on:8.2.2:*:*:*:*:*:*:*"
    ] == {"CVE-2019-4513", "CVE-2017-1732"}
    assert set(itertools.chain.from_iterable(cve_dataset._cpe_uri_to_cve_ids_lookup.values())) == {
        "CVE-2019-4513",
        "CVE-2017-1732",
        "CVE-2003-0001",
    }


def test_criteria_configurations_detected(cve_dataset: CVEDataset):
    cve_ids_with_criteria_configurations = {x.cve_id for x in cve_dataset._cves_with_vulnerable_configurations}
    assert cve_ids_with_criteria_configurations == {"CVE-2003-0070", "CVE-2010-2325"}

    # In both cases single configuration with two components
    for cve_id in cve_ids_with_criteria_configurations:
        assert len(cve_dataset[cve_id].vulnerable_criteria_configurations) == 1
        assert len(cve_dataset[cve_id].vulnerable_criteria_configurations[0].components) == 2


def test_cve_dset_from_json(cve_dataset_path: Path, cve_dataset: CVEDataset, tmp_path: Path):
    dset = CVEDataset.from_json(cve_dataset_path)
    assert all(x in dset for x in cve_dataset)

    compressed_path = tmp_path / "dset.json.gz"
    cve_dataset.to_json(compressed_path, compress=True)
    decompressed_dataset = CVEDataset.from_json(compressed_path, is_compressed=True)
    assert all(x in decompressed_dataset for x in cve_dataset)


def test_cve_from_to_dict(cve_dataset: CVEDataset):
    cve = cve_dataset["CVE-2003-0070"]
    dct = cve.to_dict()
    other_cve = CVE.from_dict(dct)
    assert cve == other_cve


def test_to_pandas(cve_dataset: CVEDataset):
    df = cve_dataset.to_pandas()
    assert df.shape == (len(cve_dataset), len(CVE.pandas_columns) - 1)
    assert df.index.name == "cve_id"
    assert set(df.columns) == set(CVE.pandas_columns) - {"cve_id"}


def test_serialization_missing_path():
    dummy_dset = CVEDataset({})
    with pytest.raises(SerializationError):
        dummy_dset.to_json()


# def test_enhance_with_nvd_data():
#     pass


def test_dataset_prunning(cve_dataset_path: Path, cpe_match_feed: dict):
    cve_dataset = CVEDataset.from_json(cve_dataset_path)
    cpes_to_consider = {
        CPE("D2D8310E-E0B8-4FF1-86EA-24F463E9F175", "cpe:2.3:o:freebsd:freebsd:4.2:*:*:*:*:*:*:*"),
        CPE("ACFEB8AA-B8FC-49E1-98BE-3D581655FE2E", "cpe:2.3:a:ibm:websphere_application_server:7.0.0.6:*:*:*:*:*:*:*"),
        CPE("88CA7428-3329-4E07-84CB-428DB1D2BC8E", "cpe:2.3:o:ibm:zos:6.0.1:*:*:*:*:*:*:*"),
    }
    cve_dataset.build_lookup_dict(cpe_match_feed, cpes_to_consider)

    assert cve_dataset._cves_with_vulnerable_configurations == [cve_dataset["CVE-2010-2325"]]
    assert cve_dataset._cpe_uri_to_cve_ids_lookup == {"cpe:2.3:o:freebsd:freebsd:4.2:*:*:*:*:*:*:*": {"CVE-2003-0001"}}


def test_criteria_configuration_expansion(cve_dataset_path: Path, cpe_match_feed: dict):
    cve_dataset = CVEDataset.from_json(cve_dataset_path)
    cve_dataset.cves = {"CVE-2003-0070": cve_dataset["CVE-2003-0070"]}
    cve_dataset.build_lookup_dict(cpe_match_feed)
    assert len(cve_dataset["CVE-2003-0070"].vulnerable_criteria_configurations) == 1
    expanded_components = cve_dataset["CVE-2003-0070"].vulnerable_criteria_configurations[0]._expanded_components
    assert len(expanded_components) == 2
    first, second = expanded_components[0], expanded_components[1]
    assert len(first) == 10
    assert "cpe:2.3:a:nalin_dahyabhai:vte:0.16.14:*:*:*:*:*:*:*" in first
    assert "cpe:2.3:a:nalin_dahyabhai:vte:0.25.1:*:*:*:*:*:*:*" in first
    assert second == [
        "cpe:2.3:a:gnome:gnome-terminal:2.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:gnome:gnome-terminal:2.2:*:*:*:*:*:*:*",
    ]
