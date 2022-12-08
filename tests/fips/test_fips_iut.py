from pathlib import Path

import pytest

import tests.data.fips.iut
from sec_certs.dataset import IUTDataset
from sec_certs.sample import IUTSnapshot


@pytest.fixture(scope="module")
def data_dir() -> Path:
    return Path(tests.data.fips.iut.__path__[0])


@pytest.fixture(scope="module")
def data_dump_path(data_dir: Path) -> Path:
    return data_dir / "fips_iut_2020-10-25T06+01:00.html"


def test_iut_dataset_from_dumps(data_dir: Path):
    dset = IUTDataset.from_dumps(data_dir)
    assert dset
    assert len(dset) == 2


def test_iut_dataset_from_web_latest():
    assert IUTDataset.from_web_latest()


def test_iut_snapshot_from_dump(data_dump_path: Path):
    assert IUTSnapshot.from_dump(data_dump_path)


def test_iut_snapshot_from_web():
    assert IUTSnapshot.from_web()


def test_iut_snapshot_from_web_latest():
    assert IUTSnapshot.from_web_latest()
