from __future__ import annotations

from importlib import resources

import pytest
import tests.data.common
import tests.data.fips.dataset

from sec_certs.dataset import CPEDataset, CVEDataset
from sec_certs.dataset.fips import FIPSDataset


@pytest.fixture(scope="module")
def toy_static_dataset() -> FIPSDataset:
    with resources.path(tests.data.fips.dataset, "toy_dataset.json") as dataset_path:
        return FIPSDataset.from_json(dataset_path)


@pytest.fixture(scope="module")
def processed_dataset(
    toy_static_dataset: FIPSDataset, cpe_dataset: CPEDataset, cve_dataset: CVEDataset, tmp_path_factory
) -> FIPSDataset:
    tmp_dir = tmp_path_factory.mktemp("fips_dset")
    toy_static_dataset.copy_dataset(tmp_dir)

    tested_certs = [
        toy_static_dataset["3095"],
        toy_static_dataset["3093"],
        toy_static_dataset["3197"],
        toy_static_dataset["2441"],
    ]
    toy_static_dataset.certs = {x.dgst: x for x in tested_certs}

    toy_static_dataset.download_all_artifacts()
    toy_static_dataset.convert_all_pdfs()
    toy_static_dataset.extract_data()
    toy_static_dataset._compute_references(keep_unknowns=True)

    toy_static_dataset.auxiliary_datasets.cpe_dset = cpe_dataset
    toy_static_dataset.auxiliary_datasets.cve_dset = cve_dataset
    toy_static_dataset.compute_cpe_heuristics()
    toy_static_dataset.compute_related_cves()
    toy_static_dataset._compute_transitive_vulnerabilities()

    return toy_static_dataset


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


def test_match_cpe(processed_dataset: FIPSDataset):
    assert processed_dataset["2441"].heuristics.cpe_matches == {"cpe:2.3:o:redhat:enterprise_linux:7.1:*:*:*:*:*:*:*"}


def test_find_related_cves(processed_dataset: FIPSDataset):
    assert processed_dataset.auxiliary_datasets.cve_dset
    processed_dataset.auxiliary_datasets.cve_dset._cpe_uri_to_cve_ids_lookup[
        "cpe:2.3:o:redhat:enterprise_linux:7.1:*:*:*:*:*:*:*"
    ] = {"CVE-123456"}
    processed_dataset.compute_related_cves()
    assert processed_dataset["2441"].heuristics.related_cves == {"CVE-123456"}


def test_find_related_cves_criteria_configuration(processed_dataset: FIPSDataset):
    processed_dataset["2441"].heuristics.cpe_matches = {
        "cpe:2.3:a:nalin_dahyabhai:vte:0.11.21:*:*:*:*:*:*:*",
        "cpe:2.3:a:gnome:gnome-terminal:2.2:*:*:*:*:*:*:*",
    }
    processed_dataset.compute_related_cves()
    assert processed_dataset["2441"].heuristics.related_cves == {"CVE-2003-0070"}


def test_keywords_heuristics(processed_dataset: FIPSDataset):
    keywords = processed_dataset["2441"].pdf_data.keywords
    assert keywords
    assert keywords["symmetric_crypto"]["AES_competition"]["AES"]["AES"] == 53
    assert not keywords["pq_crypto"]
    assert keywords["crypto_library"]["OpenSSL"]["OpenSSL"] == 83
    assert keywords["side_channel_analysis"]["SCA"]["timing attacks"] == 1
