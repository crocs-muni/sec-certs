from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from dateutil.parser import isoparse

import tests.data.cc.analysis.auxiliary_datasets
from sec_certs.dataset import CVEDataset
from sec_certs.sample import CVE
from sec_certs.sample.cpe import CPE
from sec_certs.serialization.json import SerializationError


@pytest.fixture(scope="module")
def cve_dataset_path() -> Path:
    return Path(tests.data.cc.analysis.auxiliary_datasets.__path__[0]) / "cve_dataset.json"


@pytest.fixture(scope="module")
def cve_dset(cves: list[CVE]) -> CVEDataset:
    cve_dset = CVEDataset({x.cve_id: x for x in cves})
    cve_dset.build_lookup_dict(use_nist_mapping=False)
    return cve_dset


@pytest.fixture(scope="module")
def cve_dict() -> dict[str, Any]:
    return {
        "cve_id": "CVE-1999-0001",
        "vulnerable_cpes": [
            {
                "uri": "cpe:2.3:o:freebsd:freebsd:1.0:*:*:*:*:*:*:*",
                "title": None,
                "start_version": None,
                "end_version": None,
            }
        ],
        "vulnerable_cpe_configurations": [],
        "impact": {
            "_type": "Impact",
            "base_score": 5,
            "severity": "MEDIUM",
            "explotability_score": 10,
            "impact_score": 2.9,
        },
        "published_date": "1999-12-30T05:00:00+00:00",
        "cwe_ids": {"CWE-20"},
    }


@pytest.fixture(scope="module")
def cve_2010_2325_cpe_configs() -> list[CPE]:
    return [
        CPE("cpe:2.3:a:ibm:websphere_application_server:*:*:*:*:*:*:*:*"),
        CPE("cpe:2.3:a:ibm:websphere_application_server:7.0.0.1:*:*:*:*:*:*:*"),
        CPE("cpe:2.3:a:ibm:websphere_application_server:7.0.0.2:*:*:*:*:*:*:*"),
        CPE("cpe:2.3:a:ibm:websphere_application_server:7.0.0.3:*:*:*:*:*:*:*"),
        CPE("cpe:2.3:a:ibm:websphere_application_server:7.0.0.4:*:*:*:*:*:*:*"),
        CPE("cpe:2.3:a:ibm:websphere_application_server:7.0.0.5:*:*:*:*:*:*:*"),
        CPE("cpe:2.3:a:ibm:websphere_application_server:7.0.0.6:*:*:*:*:*:*:*"),
        CPE("cpe:2.3:a:ibm:websphere_application_server:7.0.0.7:*:*:*:*:*:*:*"),
        CPE("cpe:2.3:a:ibm:websphere_application_server:7.0.0.8:*:*:*:*:*:*:*"),
        CPE("cpe:2.3:a:ibm:websphere_application_server:7.0.0.9:*:*:*:*:*:*:*"),
        CPE("cpe:2.3:a:ibm:websphere_application_server:7.0:*:*:*:*:*:*:*"),
    ]


@pytest.fixture(scope="module")
def cves(cve_2010_2325_cpe_configs) -> list[CVE]:
    cpe_single_sign_on = CPE(
        "cpe:2.3:a:ibm:security_access_manager_for_enterprise_single_sign-on:8.2.2:*:*:*:*:*:*:*",
        "IBM Security Access Manager For Enterprise Single Sign-On 8.2.2",
    )

    return [
        CVE(
            "CVE-2017-1732",
            [cpe_single_sign_on],
            [],
            CVE.Metrics(5.3, "MEDIUM", 3.9, 1.4),
            isoparse("2021-05-26T04:15Z"),
            {"CWE-200"},
        ),
        CVE(
            "CVE-2019-4513",
            [cpe_single_sign_on],
            [],
            CVE.Metrics(8.2, "HIGH", 3.9, 4.2),
            isoparse("2000-05-26T04:15Z"),
            {"CWE-611"},
        ),
        CVE(
            "CVE-2010-2325",
            [],
            cve_2010_2325_cpe_configs,
            CVE.Metrics(4.3, "MEDIUM", 8.6, 2.9),
            isoparse("2010-06-18T18:30"),
            {"CWE-79"},
        ),
    ]


@pytest.mark.slow
@pytest.mark.monitor_test
@pytest.mark.xfail(reason="May fail due to errors on NIST server.")
def test_from_web():
    dset = CVEDataset.from_web()
    assert dset is not None
    assert "CVE-2019-15809" in dset.cves
    assert "CVE-2017-15361" in dset.cves


def test_cve_dset_lookup_dicts(cve_dset: CVEDataset):
    alt_lookup = {x: set(y) for x, y in cve_dset.cpe_uri_to_cve_ids_lookup.items()}
    assert alt_lookup == {
        "cpe:2.3:a:ibm:security_access_manager_for_enterprise_single_sign-on:8.2.2:*:*:*:*:*:*:*": {
            "CVE-2017-1732",
            "CVE-2019-4513",
        }
    }


def test_cve_dset_from_json(cve_dataset_path: Path, cve_dset: CVEDataset, tmp_path: Path):
    dset = CVEDataset.from_json(cve_dataset_path)
    assert all(x in dset for x in cve_dset)

    compressed_path = tmp_path / "dset.json.gz"
    cve_dset.to_json(compressed_path, compress=True)
    decompressed_dataset = CVEDataset.from_json(compressed_path, is_compressed=True)
    assert all(x in decompressed_dataset for x in cve_dset)


def test_cve_from_to_dict(cve_dict: dict[str, Any]):
    cve = CVE.from_dict(cve_dict)
    ret = cve.to_dict()
    assert ret == cve_dict
    other_cve = CVE.from_dict(ret)
    assert cve == other_cve


def test_to_pandas(cve_dset: CVEDataset):
    df = cve_dset.to_pandas()
    assert df.shape == (len(cve_dset), len(CVE.pandas_columns) - 1)
    assert df.index.name == "cve_id"
    assert set(df.columns) == set(CVE.pandas_columns) - {"cve_id"}


def test_serialization_missing_path():
    dummy_dset = CVEDataset({})
    with pytest.raises(SerializationError):
        dummy_dset.to_json()
