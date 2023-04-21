from __future__ import annotations

import tempfile

import pytest

from sec_certs.dataset.cc import CCDataset


@pytest.fixture(scope="module")
def processed_cc_dataset() -> CCDataset:
    with tempfile.TemporaryDirectory() as tmp_dir:
        cc_dset = CCDataset(root_dir=tmp_dir)
        cc_dset.get_certs_from_web()
        cc_dset._prepare_cpe_dataset()
        cc_dset._prepare_cve_dataset()
        cc_dset._prepare_cpe_match_dict()
        cc_dset.compute_cpe_heuristics()
        cc_dset.compute_related_cves()
        return cc_dset


roca_expected_matches = [
    ("15d68159595eae09", {"CVE-2017-15361"}),
    ("e93cb94a06c6957e", {"CVE-2017-15361"}),
    ("6ff89f3123a6a98f", {"CVE-2017-15361"}),
    ("cdf0face8adbf285", {"CVE-2017-15361"}),
    ("c96ac4c4015414ad", {"CVE-2017-15361"}),
    ("7e9dd6cb86b58f95", {"CVE-2017-15361"}),
    ("446aa68e0c4c5083", {"CVE-2017-15361"}),
    ("d3323745a51a604d", {"CVE-2017-15361"}),
    ("13c393fa406a72cb", {"CVE-2017-15361"}),
    ("f6934fa14d46e748", {"CVE-2017-15361"}),
    ("b584e424a8b3dabe", {"CVE-2017-15361"}),
    ("7f4d3b659fc17c09", {"CVE-2017-15361"}),
    ("5efe98a1ba4df4d7", {"CVE-2017-15361"}),
    ("9be76c10474e0c80", {"CVE-2017-15361"}),
    ("e2e705cabd42e40e", {"CVE-2017-15361"}),
    ("8eb6fca41668f95b", {"CVE-2017-15361"}),
]

titan_expected_matches = [
    ("2793414918738c7f", {"CVE-2021-3011"}),
    ("dbe20d7c305b24eb", {"CVE-2021-3011"}),
    ("559a5c3c4c23a9d3", {"CVE-2021-3011"}),
    ("861434b03ddcac64", {"CVE-2021-3011"}),
    ("8cfd0c9f4bcd21b8", {"CVE-2021-3011"}),
    ("b24a14935edd51ad", {"CVE-2021-3011"}),
    ("36ed04f4b45e3ab9", {"CVE-2021-3011"}),
]


@pytest.mark.parametrize("dgst,expected_cves", roca_expected_matches)
@pytest.mark.skip(reason="Slow end-to-end test meant to be run when CVE/CPE matching changes.")
def test_roca_matches(processed_cc_dataset: CCDataset, dgst: str, expected_cves: set[str]):
    related_cves = processed_cc_dataset[dgst].heuristics.related_cves
    assert related_cves
    assert related_cves.issuperset(expected_cves)


@pytest.mark.parametrize("dgst,expected_cves", titan_expected_matches)
@pytest.mark.skip(reason="Slow end-to-end test meant to be run when CVE/CPE matching changes.")
def test_titan_matches(processed_cc_dataset: CCDataset, dgst: str, expected_cves: set[str]):
    related_cves = processed_cc_dataset[dgst].heuristics.related_cves
    assert related_cves
    assert related_cves.issuperset(expected_cves)
