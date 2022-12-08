from __future__ import annotations

from pathlib import Path

import pytest

import tests.data.fips.dataset
from sec_certs.dataset import CPEDataset, CVEDataset
from sec_certs.dataset.fips import FIPSDataset
from sec_certs.sample.cpe import CPE
from sec_certs.sample.cve import CVE


@pytest.fixture(scope="module")
def data_dir() -> Path:
    return Path(tests.data.fips.dataset.__path__[0])


@pytest.fixture(scope="module")
def vulnerable_cpe() -> CPE:
    return CPE("cpe:2.3:o:redhat:enterprise_linux:7.1:*:*:*:*:*:*:*", "Red Hat Enterprise Linux 7.1")


@pytest.fixture(scope="module")
def some_random_cpe() -> CPE:
    return CPE(
        "cpe:2.3:a:ibm:security_key_lifecycle_manager:2.6.0.1:*:*:*:*:*:*:*",
        "IBM Security Key Lifecycle Manager 2.6.0.1",
    )


@pytest.fixture(scope="module")
def cve(vulnerable_cpe: CPE) -> CVE:
    return CVE(
        "CVE-1234-123456",
        [vulnerable_cpe],
        CVE.Impact(10, "HIGH", 10, 10),
        "2021-05-26T04:15Z",
        {"CWE-200"},
    )


@pytest.fixture(scope="module")
def some_other_cve(some_random_cpe: CPE) -> CVE:
    return CVE(
        "CVE-2019-4513",
        [some_random_cpe],
        CVE.Impact(8.2, "HIGH", 3.9, 4.2),
        "2000-05-26T04:15Z",
        {"CVE-611"},
    )


@pytest.fixture(scope="module")
def cpe_dataset(vulnerable_cpe: CPE, some_random_cpe: CPE) -> CPEDataset:
    cpes = {
        vulnerable_cpe,
        some_random_cpe,
        CPE(
            "cpe:2.3:a:semperplugins:all_in_one_seo_pack:1.3.6.4:*:*:*:*:wordpress:*:*",
            "Semper Plugins All in One SEO Pack 1.3.6.4 for WordPress",
        ),
        CPE(
            "cpe:2.3:a:tracker-software:pdf-xchange_lite_printer:6.0.320.0:*:*:*:*:*:*:*",
            "Tracker Software PDF-XChange Lite Printer 6.0.320.0",
        ),
    }
    return CPEDataset(False, {x.uri: x for x in cpes})


@pytest.fixture(scope="module")
def cve_dataset(cve: CVE, some_other_cve: CVE) -> CVEDataset:
    cves = {cve, some_other_cve}
    cve_dset = CVEDataset({x.cve_id: x for x in cves})
    cve_dset.build_lookup_dict(use_nist_mapping=False)
    return cve_dset


@pytest.fixture(scope="module")
def toy_static_dataset(data_dir: Path) -> FIPSDataset:
    return FIPSDataset.from_json(data_dir / "toy_dataset.json")


@pytest.fixture(scope="module")
def processed_dataset(
    toy_static_dataset: FIPSDataset, cpe_dataset: CPEDataset, cve_dataset: CVEDataset, tmp_path_factory
) -> FIPSDataset:
    tmp_dir = tmp_path_factory.mktemp("cc_dset")
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

    toy_static_dataset.auxillary_datasets.cpe_dset = cpe_dataset
    toy_static_dataset.auxillary_datasets.cve_dset = cve_dataset
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


def test_match_cpe(processed_dataset: FIPSDataset, vulnerable_cpe: CPE, some_random_cpe: CPE):
    assert processed_dataset["2441"].heuristics.cpe_matches
    assert vulnerable_cpe.uri in processed_dataset["2441"].heuristics.cpe_matches
    assert some_random_cpe.uri not in processed_dataset["2441"].heuristics.cpe_matches


def test_find_related_cves(processed_dataset: FIPSDataset, cve: CVE, some_other_cve: CVE):
    assert processed_dataset["2441"].heuristics.related_cves
    assert cve.cve_id in processed_dataset["2441"].heuristics.related_cves
    assert some_other_cve not in processed_dataset["2441"].heuristics.related_cves


def test_keywords_heuristics(processed_dataset: FIPSDataset):
    keywords = processed_dataset["2441"].pdf_data.keywords
    assert keywords
    assert keywords["symmetric_crypto"]["AES_competition"]["AES"]["AES"] == 53
    assert not keywords["pq_crypto"]
    assert keywords["crypto_library"]["OpenSSL"]["OpenSSL"] == 83
    assert keywords["side_channel_analysis"]["SCA"]["timing attacks"] == 1
