from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from sec_certs.dataset.auxiliary_dataset_handling import CPEDatasetHandler, CVEDatasetHandler
from sec_certs.dataset.fips import FIPSDataset
from sec_certs.heuristics.common import compute_related_cves
from sec_certs.serialization.schemas import validator


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
    assert processed_dataset.aux_handlers[CVEDatasetHandler].dset
    processed_dataset.aux_handlers[CVEDatasetHandler].dset._cpe_uri_to_cve_ids_lookup[
        "cpe:2.3:o:redhat:enterprise_linux:7.1:*:*:*:*:*:*:*"
    ] = {"CVE-123456"}
    compute_related_cves(
        processed_dataset.aux_handlers[CPEDatasetHandler].dset,
        processed_dataset.aux_handlers[CVEDatasetHandler].dset,
        {},
        processed_dataset.certs.values(),
    )
    assert processed_dataset["2441"].heuristics.related_cves == {"CVE-123456"}


def test_find_related_cves_criteria_configuration(processed_dataset: FIPSDataset):
    processed_dataset["2441"].heuristics.cpe_matches = {
        "cpe:2.3:a:nalin_dahyabhai:vte:0.11.21:*:*:*:*:*:*:*",
        "cpe:2.3:a:gnome:gnome-terminal:2.2:*:*:*:*:*:*:*",
    }
    compute_related_cves(
        processed_dataset.aux_handlers[CPEDatasetHandler].dset,
        processed_dataset.aux_handlers[CVEDatasetHandler].dset,
        {},
        processed_dataset.certs.values(),
    )
    assert processed_dataset["2441"].heuristics.related_cves == {"CVE-2003-0070"}


def test_keywords_heuristics(processed_dataset: FIPSDataset):
    keywords = processed_dataset["2441"].pdf_data.keywords
    assert keywords
    assert keywords["symmetric_crypto"]["AES_competition"]["AES"]["AES"] == 67
    assert not keywords["pq_crypto"]
    assert keywords["crypto_library"]["OpenSSL"]["OpenSSL"] == 83
    assert keywords["side_channel_analysis"]["SCA"]["timing attacks"] == 1


def test_schema_validate(processed_dataset: FIPSDataset):
    with TemporaryDirectory() as tmp_dir:
        single_v = validator("http://sec-certs.org/schemas/fips_certificate.json")
        for cert in processed_dataset:
            fname = Path(tmp_dir) / (cert.dgst + ".json")
            cert.to_json(fname)
            with fname.open("r") as handle:
                single_v.validate(json.load(handle))

        dset_v = validator("http://sec-certs.org/schemas/fips_dataset.json")
        fname = Path(tmp_dir) / "dset.json"
        processed_dataset.to_json(fname)
        with fname.open("r") as handle:
            dset_v.validate(json.load(handle))
