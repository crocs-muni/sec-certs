from __future__ import annotations

import pytest

from sec_certs.dataset.cve import CVEDataset
from sec_certs.dataset.fips import FIPSDataset
from sec_certs.sample.cpe import CPE
from sec_certs.sample.cve import CVE


@pytest.mark.parametrize(
    "input_dgst, expected_refs",
    [
        ("3095", {"3093", "3094", "3096"}),
        ("3093", {"3090", "3091"}),
        ("3197", {"3195", "3096", "3196", "3644", "3651"}),
    ],
)
def test_html_modules_directly_referencing(processed_dataset: FIPSDataset, input_dgst: str, expected_refs: set[str]):
    crt = processed_dataset[input_dgst]
    if not crt.state.module_extract_ok:
        pytest.xfail(reason="Data from module not extracted")
    assert crt.heuristics.module_processed_references.directly_referencing == expected_refs


@pytest.mark.parametrize("input_dgst, expected_refs", [("3095", {"3093", "3094", "3096"}), ("3093", {"3090", "3091"})])
def test_pdf_policies_directly_referencing(processed_dataset: FIPSDataset, input_dgst: str, expected_refs: set[str]):
    crt = processed_dataset[input_dgst]
    if not crt.state.policy_extract_ok:
        pytest.xfail(reason="Data from policy not extracted")
    assert crt.heuristics.policy_processed_references.directly_referencing == expected_refs


@pytest.mark.parametrize(
    "input_dgst, expected_refs",
    [
        (
            "3093",
            {
                "3090",
                "3091",
            },
        ),
        ("3095", {"3090", "3091", "3093", "3094", "3096"}),
    ],
)
def test_html_modules_indirectly_referencing(processed_dataset: FIPSDataset, input_dgst: str, expected_refs: set[str]):
    crt = processed_dataset[input_dgst]
    if not crt.state.module_extract_ok:
        pytest.xfail(reason="Data from module not extracted")
    assert crt.heuristics.module_processed_references.indirectly_referencing == expected_refs


@pytest.mark.parametrize(
    "input_dgst, expected_refs",
    [("3095", {"3090", "3091", "3093", "3094", "3096"}), ("3093", {"3090", "3091"})],
)
def test_pdf_policies_indirectly_referencing(processed_dataset: FIPSDataset, input_dgst: str, expected_refs: set[str]):
    crt = processed_dataset[input_dgst]
    if not crt.state.policy_extract_ok:
        pytest.xfail(reason="Data from policy not extracted")
    assert crt.heuristics.policy_processed_references.indirectly_referencing == expected_refs


@pytest.mark.parametrize("input_dgst, expected_refs", [("3095", None), ("3093", {"3095"})])
def test_html_modules_directly_referenced_by(
    processed_dataset: FIPSDataset, input_dgst: str, expected_refs: set[str] | None
):
    crt = processed_dataset[input_dgst]
    if not crt.state.module_extract_ok:
        pytest.xfail(reason="Data from module not extracted")
    assert crt.heuristics.module_processed_references.directly_referenced_by == expected_refs


@pytest.mark.parametrize("input_dgst, expected_refs", [("3095", None), ("3093", {"3095"})])
def test_pdf_policies_directly_referenced_by(
    processed_dataset: FIPSDataset, input_dgst: str, expected_refs: set[str] | None
):
    crt = processed_dataset[input_dgst]
    if not crt.state.policy_extract_ok:
        pytest.xfail(reason="Data from policy not extracted")
    assert crt.heuristics.policy_processed_references.directly_referenced_by == expected_refs


@pytest.mark.parametrize("input_dgst, expected_refs", [("3095", None), ("3093", {"3095"})])
def test_html_modules_indirectly_referenced_by(
    processed_dataset: FIPSDataset, input_dgst: str, expected_refs: set[str] | None
):
    crt = processed_dataset[input_dgst]
    if not crt.state.module_extract_ok:
        pytest.xfail(reason="Data from module not extracted")
    assert crt.heuristics.module_processed_references.indirectly_referenced_by == expected_refs


@pytest.mark.parametrize("input_dgst, expected_refs", [("3095", None), ("3093", {"3095"})])
def test_pdf_policies_indirectly_referenced_by(
    processed_dataset: FIPSDataset, input_dgst: str, expected_refs: set[str] | None
):
    crt = processed_dataset[input_dgst]
    if not crt.state.policy_extract_ok:
        pytest.xfail(reason="Data from module not extracted")
    assert crt.heuristics.module_processed_references.indirectly_referenced_by == expected_refs


def test_match_cpe(processed_dataset: FIPSDataset, vulnerable_cpe: CPE, some_random_cpe: CPE):
    assert processed_dataset["2441"].heuristics.cpe_matches
    assert vulnerable_cpe.uri in processed_dataset["2441"].heuristics.cpe_matches
    assert some_random_cpe.uri not in processed_dataset["2441"].heuristics.cpe_matches


def test_find_related_cves(processed_dataset: FIPSDataset, cve: CVE, some_other_cve: CVE):
    assert processed_dataset["2441"].heuristics.related_cves
    assert cve.cve_id in processed_dataset["2441"].heuristics.related_cves
    assert some_other_cve not in processed_dataset["2441"].heuristics.related_cves


def test_find_related_cves_for_cpe_configuration(
    processed_dataset: FIPSDataset,
    cve_dataset: CVEDataset,
    ibm_xss_cve: CVE,
    cpes_ibm_websphere_app_with_platform: set[CPE],
):
    cve_dataset.cves = {ibm_xss_cve.cve_id: ibm_xss_cve}
    cert = processed_dataset["2441"]
    cert.heuristics.cpe_matches = {cpe.uri for cpe in cpes_ibm_websphere_app_with_platform}
    processed_dataset.auxiliary_datasets.cve_dset = cve_dataset
    processed_dataset.compute_related_cves()
    assert cert.heuristics.related_cves == {ibm_xss_cve.cve_id}


def test_keywords_heuristics(processed_dataset: FIPSDataset):
    keywords = processed_dataset["2441"].pdf_data.keywords
    assert keywords
    assert keywords["symmetric_crypto"]["AES_competition"]["AES"]["AES"] == 53
    assert not keywords["pq_crypto"]
    assert keywords["crypto_library"]["OpenSSL"]["OpenSSL"] == 83
    assert keywords["side_channel_analysis"]["SCA"]["timing attacks"] == 1
