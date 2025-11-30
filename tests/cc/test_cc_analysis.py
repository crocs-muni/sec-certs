from __future__ import annotations

import json
import shutil
from collections.abc import Generator
from importlib.resources import as_file, files
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
import tests.data.cc.analysis
import tests.data.common

from sec_certs.cert_rules import SARS_IMPLIED_FROM_EAL
from sec_certs.dataset.auxiliary_dataset_handling import (
    CPEDatasetHandler,
    CPEMatchDictHandler,
    CVEDatasetHandler,
    ProtectionProfileDatasetHandler,
)
from sec_certs.dataset.cc import CCDataset
from sec_certs.dataset.cpe import CPEDataset
from sec_certs.dataset.cve import CVEDataset
from sec_certs.heuristics.common import compute_related_cves, compute_transitive_vulnerabilities, compute_references
from sec_certs.model.references_nlp.segment_extractor import ReferenceSegmentExtractor
from sec_certs.sample.cc import CCCertificate
from sec_certs.sample.sar import SAR
from sec_certs.serialization.schemas import validator


@pytest.fixture(scope="module")
def analysis_data_dir() -> Generator[Path, None, None]:
    with as_file(files(tests.data.cc.analysis)) as path:
        yield path


@pytest.fixture(scope="module")
def processed_cc_dset(
    analysis_data_dir: Path, cve_dataset: CVEDataset, cpe_dataset: CPEDataset, tmp_path_factory, pp_data_dir: Path
) -> CCDataset:
    tmp_dir = tmp_path_factory.mktemp("cc_dset")
    shutil.copytree(analysis_data_dir, tmp_dir, dirs_exist_ok=True)

    cc_dset = CCDataset.from_json(tmp_dir / "vulnerable_dataset.json")
    cc_dset.aux_handlers[ProtectionProfileDatasetHandler].root_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(pp_data_dir / "dataset.json", cc_dset.aux_handlers[ProtectionProfileDatasetHandler].dset_path)

    cc_dset.aux_handlers[ProtectionProfileDatasetHandler].process_dataset()
    cc_dset.aux_handlers[CPEMatchDictHandler].dset = {}
    cc_dset.aux_handlers[CVEDatasetHandler].dset = cve_dataset
    cc_dset.aux_handlers[CPEDatasetHandler].dset = cpe_dataset

    cc_dset.extract_data()
    cc_dset._compute_heuristics_body(skip_schemes=True)

    return cc_dset


@pytest.fixture
def reference_dataset(analysis_data_dir: Path, tmp_path_factory) -> CCDataset:
    tmp_dir = tmp_path_factory.mktemp("cc_dset")
    shutil.copytree(analysis_data_dir, tmp_dir, dirs_exist_ok=True)
    return CCDataset.from_json(tmp_dir / "reference_dataset.json")


@pytest.fixture
def transitive_vulnerability_dataset(analysis_data_dir) -> CCDataset:
    return CCDataset.from_json(analysis_data_dir / "transitive_vulnerability_dataset.json")


@pytest.fixture
def random_certificate(processed_cc_dset: CCDataset) -> CCCertificate:
    return processed_cc_dset["ed91ff3e658457fd"]


def test_match_cpe(random_certificate: CCCertificate):
    assert {
        "cpe:2.3:a:ibm:security_access_manager_for_enterprise_single_sign-on:8.2.2:*:*:*:*:*:*:*"
    } == random_certificate.heuristics.cpe_matches


def test_find_related_cves(processed_cc_dset: CCDataset, random_certificate: CCCertificate):
    random_certificate.heuristics.cpe_matches = {
        "cpe:2.3:a:ibm:security_access_manager_for_enterprise_single_sign-on:8.2.2:*:*:*:*:*:*:*"
    }
    compute_related_cves(
        processed_cc_dset.aux_handlers[CPEDatasetHandler].dset,
        processed_cc_dset.aux_handlers[CVEDatasetHandler].dset,
        {},
        processed_cc_dset.certs.values(),
    )

    assert random_certificate.heuristics.related_cves == {"CVE-2017-1732", "CVE-2019-4513"}


def test_find_related_cves_criteria_configuration(processed_cc_dset: CCDataset, random_certificate: CCCertificate):
    random_certificate.heuristics.cpe_matches = {
        "cpe:2.3:a:ibm:websphere_application_server:7.0:*:*:*:*:*:*:*",
        "cpe:2.3:o:ibm:zos:6.0.1:*:*:*:*:*:*:*",
    }

    compute_related_cves(
        processed_cc_dset.aux_handlers[CPEDatasetHandler].dset,
        processed_cc_dset.aux_handlers[CVEDatasetHandler].dset,
        {},
        processed_cc_dset.certs.values(),
    )

    assert random_certificate.heuristics.related_cves == {"CVE-2010-2325"}


def test_version_extraction(random_certificate: CCCertificate):
    assert random_certificate.heuristics.extracted_versions == {"8.2"}

    new_cert = CCCertificate(
        "",
        "",
        "IDOneClassIC Card : ID-One Cosmo 64 RSA v5.4 and applet IDOneClassIC v1.0 embedded on P5CT072VOP",
        "",
        "",
        "",
        None,
        None,
        "",
        "",
        "",
        "",
        set(),
        set(),
        None,
        None,
        None,
    )
    new_cert.compute_heuristics_version()
    assert new_cert.heuristics.extracted_versions == {"5.4", "1.0"}


def test_cert_lab_heuristics(random_certificate: CCCertificate):
    assert random_certificate.heuristics.cert_lab == ["BSI"]


def test_cert_id_heuristics(random_certificate: CCCertificate):
    assert random_certificate.heuristics.cert_id == "BSI-DSZ-CC-0683-2014"


def test_keywords_heuristics(random_certificate: CCCertificate):
    assert random_certificate.pdf_data.st_keywords
    extracted_keywords: dict = random_certificate.pdf_data.st_keywords

    assert "cc_security_level" in extracted_keywords
    assert extracted_keywords["cc_security_level"]["EAL"]["EAL3"] == 1
    assert "cc_sar" in extracted_keywords

    assert extracted_keywords["cc_sar"]["ADV"]["ADV_ARC.1"] == 1
    assert extracted_keywords["cc_sar"]["ADV"]["ADV_FSP.3"] == 1
    assert extracted_keywords["cc_sar"]["ADV"]["ADV_TDS.2"] == 1

    assert "symmetric_crypto" in extracted_keywords
    assert extracted_keywords["symmetric_crypto"]["AES_competition"]["AES"]["AES"] == 2

    assert "cipher_mode" in extracted_keywords
    assert extracted_keywords["cipher_mode"]["CBC"]["CBC"] == 2


def test_single_record_references_heuristics(random_certificate: CCCertificate):
    # Single record in daset is not affecting nor affected by other records
    assert not random_certificate.heuristics.report_references.directly_referenced_by
    assert not random_certificate.heuristics.report_references.indirectly_referenced_by
    assert not random_certificate.heuristics.report_references.directly_referencing
    assert not random_certificate.heuristics.report_references.indirectly_referencing


def test_reference_dataset(reference_dataset: CCDataset):
    compute_references(reference_dataset.certs)

    test_cert = reference_dataset["d1b238729b25d745"]

    assert test_cert.heuristics.report_references.directly_referenced_by == {"BSI-DSZ-CC-0370-2006"}
    assert test_cert.heuristics.report_references.indirectly_referenced_by == {
        "BSI-DSZ-CC-0370-2006",
        "BSI-DSZ-CC-0517-2009",
    }
    assert not test_cert.heuristics.report_references.directly_referencing
    assert not test_cert.heuristics.report_references.indirectly_referencing


def test_direct_transitive_vulnerability_dataset(transitive_vulnerability_dataset: CCDataset):
    compute_transitive_vulnerabilities(transitive_vulnerability_dataset.certs)
    assert transitive_vulnerability_dataset["11f77cb31b931a57"].heuristics.direct_transitive_cves == {"CVE-2013-5385"}


def test_indirect_transitive_vulnerability_dataset(transitive_vulnerability_dataset: CCDataset):
    compute_transitive_vulnerabilities(transitive_vulnerability_dataset.certs)
    assert transitive_vulnerability_dataset["11f77cb31b931a57"].heuristics.indirect_transitive_cves == {"CVE-2013-5385"}


def test_sar_object():
    alc_flr_one = SAR("ALC_FLR", 1)
    alc_flr_one_copy = SAR("ALC_FLR", 1)
    alc_flr_two = SAR("ALC_FLR", 2)

    assert alc_flr_one == alc_flr_one_copy
    assert alc_flr_one != alc_flr_two

    with pytest.raises(ValueError):
        # does not contain level
        SAR.from_string("ALC_FLR")

    with pytest.raises(ValueError):
        # unknown family
        SAR.from_string("XALC_FLR")


def test_sar_transformation(random_certificate: CCCertificate):
    assert random_certificate.heuristics.extracted_sars

    # This one should be taken from security level and not overwritten by stronger SARs in ST
    assert SAR("ALC_FLR", 1) in random_certificate.heuristics.extracted_sars
    assert SAR("ALC_FLR", 2) not in random_certificate.heuristics.extracted_sars

    # This one should be taken from ST and not overwritten by stronger SAR in report
    assert SAR("ADV_FSP", 3) in random_certificate.heuristics.extracted_sars
    assert SAR("ADV_FSP", 6) not in random_certificate.heuristics.extracted_sars


def test_eal_implied_sar_inference(random_certificate: CCCertificate):
    assert random_certificate.actual_sars

    actual_sars = random_certificate.actual_sars
    eal_3_sars = {SAR(x[0], x[1]) for x in SARS_IMPLIED_FROM_EAL["EAL3"]}
    assert eal_3_sars.issubset(actual_sars)


def test_eal_inference(processed_cc_dset: CCDataset):
    assert processed_cc_dset["ed91ff3e658457fd"].heuristics.eal == "EAL1"
    assert processed_cc_dset["95e3850bef32f410"].heuristics.eal == "EAL1+"


def test_pp_linking(processed_cc_dset: CCDataset):
    assert processed_cc_dset["ed91ff3e658457fd"].heuristics.protection_profiles == {"e315e3e834a61448"}
    assert processed_cc_dset["95e3850bef32f410"].heuristics.protection_profiles == {
        "b02ed76d2545326a",
        "c8b175590bb7fdfb",
    }
    pp_dset = processed_cc_dset.aux_handlers[ProtectionProfileDatasetHandler].dset
    assert processed_cc_dset["ed91ff3e658457fd"].protection_profile_links
    assert processed_cc_dset["95e3850bef32f410"].protection_profile_links
    assert (
        pp_dset["e315e3e834a61448"].web_data.pp_link in processed_cc_dset["ed91ff3e658457fd"].protection_profile_links
    )
    assert (
        pp_dset["b02ed76d2545326a"].web_data.pp_link in processed_cc_dset["95e3850bef32f410"].protection_profile_links
    )
    assert (
        pp_dset["c8b175590bb7fdfb"].web_data.pp_link in processed_cc_dset["95e3850bef32f410"].protection_profile_links
    )


def test_segment_extractor(reference_dataset: CCDataset):
    df = ReferenceSegmentExtractor()(reference_dataset.certs.values())
    assert df is not None
    assert not df.empty


def test_schema_validate(reference_dataset: CCDataset):
    with TemporaryDirectory() as tmp_dir:
        single_v = validator("http://sec-certs.org/schemas/cc_certificate.json")
        for cert in reference_dataset:
            fname = Path(tmp_dir) / (cert.dgst + ".json")
            cert.to_json(fname)
            with fname.open("r") as handle:
                single_v.validate(json.load(handle))

        dset_v = validator("http://sec-certs.org/schemas/cc_dataset.json")
        fname = Path(tmp_dir) / "dset.json"
        reference_dataset.to_json(fname)
        with fname.open("r") as handle:
            dset_v.validate(json.load(handle))
