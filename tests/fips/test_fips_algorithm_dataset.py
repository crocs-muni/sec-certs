from __future__ import annotations

from importlib import resources
from typing import Any

import pytest
import tests.data.fips.dataset

from sec_certs.dataset.fips_algorithm import FIPSAlgorithmDataset
from sec_certs.sample.fips_algorithm import FIPSAlgorithm
from sec_certs.serialization.json import SerializationError


@pytest.mark.xfail(reason="May fail due to errors with NIST server.")
@pytest.mark.slow
def test_alg_dset_from_web(tmp_path):
    dset = FIPSAlgorithmDataset.from_web(tmp_path)
    assert dset
    assert "TDES2840" in dset
    assert "SHS1619" in dset
    assert "RNG447" in dset
    assert len(dset) > 30000


@pytest.fixture(scope="module")
def alg_dset() -> FIPSAlgorithmDataset:
    with resources.path(tests.data.fips.dataset, "alg_dataset.json") as alg_dset_path:
        return FIPSAlgorithmDataset.from_json(alg_dset_path)


@pytest.fixture(scope="module")
def alg_dict() -> dict[str, Any]:
    return {
        "alg_number": "2902",
        "algorithm_type": "AES",
        "vendor": "Hewlett-Packard Development Company, L.P.",
        "implementation_name": "HP Secure Encryption Engine v1.0",
        "validation_date": "7/10/2014",
    }


def test_alg_dset_lookup_dict(alg_dset: FIPSAlgorithmDataset):
    alg = alg_dset["AES2902"]
    assert alg_dset.alg_number_to_algs["2902"] == {alg}


def test_alg_from_to_dict(alg_dict: dict[str, Any]):
    alg = FIPSAlgorithm.from_dict(alg_dict)
    ret = alg.to_dict()
    assert alg_dict == ret
    other_alg = FIPSAlgorithm.from_dict(ret)
    assert alg == other_alg


def test_to_pandas(alg_dset: FIPSAlgorithmDataset):
    df = alg_dset.to_pandas()
    assert df.shape == (len(alg_dset), len(FIPSAlgorithm.pandas_columns) - 1)
    assert df.index.name == "dgst"
    assert set(df.columns) == set(FIPSAlgorithm.pandas_columns) - {"dgst"}


def test_serialization_missing_path():
    dummy_dset = FIPSAlgorithmDataset()
    with pytest.raises(SerializationError):
        dummy_dset.to_json()
