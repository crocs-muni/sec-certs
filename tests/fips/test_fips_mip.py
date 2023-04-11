from __future__ import annotations

import datetime
from pathlib import Path

import pytest

import tests.data.fips.mip
from sec_certs.dataset import FIPSDataset, MIPDataset
from sec_certs.model import FIPSProcessMatcher
from sec_certs.sample import MIPEntry, MIPSnapshot, MIPStatus


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


def test_mip_flows():
    dset = MIPDataset.from_web_latest()
    assert dset.compute_flows()


def test_mip_snapshot_from_dump(data_dump_path: Path):
    assert MIPSnapshot.from_dump(data_dump_path)


def test_from_web():
    assert MIPSnapshot.from_web()


def test_from_web_latest():
    assert MIPSnapshot.from_web_latest()


def test_mip_matching(processed_dataset: FIPSDataset):
    entry = MIPEntry(
        module_name="Red Hat Enterprise Linux 7.1 OpenSSL Module",
        vendor_name="Red Hat(R), Inc.",
        standard="FIPS 140-2",
        status=MIPStatus.IN_REVIEW,
        status_since=datetime.date(2014, 1, 1),
    )
    matcher = FIPSProcessMatcher(entry)
    scores = [matcher.match(cert) for cert in processed_dataset]
    assert len(list(filter(lambda x: x > 90, scores))) == 1


def test_mip_snapshot_match(processed_dataset: FIPSDataset, data_dump_path: Path):
    snapshot = MIPSnapshot.from_dump(data_dump_path)
    matches = FIPSProcessMatcher.match_snapshot(snapshot, processed_dataset)
    assert matches
