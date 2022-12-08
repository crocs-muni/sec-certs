from pathlib import Path

import pytest

import tests.data.fips.mip
from sec_certs.dataset import MIPDataset
from sec_certs.sample import MIPSnapshot


@pytest.fixture(scope="module")
def data_dir() -> Path:
    return Path(tests.data.fips.mip.__path__[0])


@pytest.fixture(scope="module")
def data_dump_path(data_dir) -> Path:
    return data_dir / "fips_mip_2021-02-19T06+01:00.html"


def test_mip_dataset_from_dumps(data_dir: Path):
    dset = MIPDataset.from_dumps(data_dir)
    assert dset
    assert len(dset) == 3


def test_mip_dataset_from_dataset_latest():
    assert MIPDataset.from_web_latest()


def test_mip_snapshot_from_dump(data_dump_path: Path):
    assert MIPSnapshot.from_dump(data_dump_path)


def test_from_web():
    assert MIPSnapshot.from_web()


def test_from_web_latest():
    assert MIPSnapshot.from_web_latest()
