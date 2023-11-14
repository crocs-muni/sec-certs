from __future__ import annotations

import datetime
from collections.abc import Generator
from importlib import resources
from pathlib import Path

import pytest
import tests.data.fips.iut

from sec_certs.dataset.fips import FIPSDataset
from sec_certs.dataset.fips_iut import IUTDataset
from sec_certs.model.fips_matching import FIPSProcessMatcher
from sec_certs.sample.fips_iut import IUTEntry, IUTSnapshot


@pytest.fixture(scope="module")
def data_dir() -> Generator[Path, None, None]:
    with resources.path(tests.data.fips.iut, "") as path:
        yield path


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


def test_iut_matching(processed_dataset: FIPSDataset):
    entry = IUTEntry(
        module_name="Red Hat Enterprise Linux 7.1 OpenSSL Module",
        vendor_name="Red Hat(R), Inc.",
        standard="FIPS 140-2",
        iut_date=datetime.date(2014, 1, 1),
    )
    matcher = FIPSProcessMatcher(entry)
    scores = [matcher.match(cert) for cert in processed_dataset]
    assert len(list(filter(lambda x: x > 90, scores))) == 1


def test_iut_snapshot_match(processed_dataset: FIPSDataset, data_dump_path: Path):
    snapshot = IUTSnapshot.from_dump(data_dump_path)
    # Move snapshot date back so that there are matches
    snapshot.timestamp = datetime.datetime(2014, 1, 2)
    matches = FIPSProcessMatcher.match_snapshot(snapshot, processed_dataset)
    assert matches
