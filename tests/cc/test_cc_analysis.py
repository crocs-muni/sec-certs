from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import tests.data.cc.analysis
from sec_certs.cert_rules import SARS_IMPLIED_FROM_EAL
from sec_certs.dataset import CCDataset
from sec_certs.dataset.cpe import CPEDataset
from sec_certs.dataset.cve import CVEDataset
from sec_certs.sample.cc import CCCertificate
from sec_certs.sample.cpe import CPE
from sec_certs.sample.cve import CVE
from sec_certs.sample.protection_profile import ProtectionProfile
from sec_certs.sample.sar import SAR


@pytest.fixture(scope="module")
def data_dir() -> Path:
    return Path(tests.data.cc.analysis.__path__[0])


@pytest.fixture(scope="module")
def cpe_single_sign_on() -> CPE:
    return CPE(
        "cpe:2.3:a:ibm:security_access_manager_for_enterprise_single_sign-on:8.2.2:*:*:*:*:*:*:*",
        "IBM Security Access Manager For Enterprise Single Sign-On 8.2.2",
    )


@pytest.fixture(scope="module")
def cpes(cpe_single_sign_on: CPE) -> set[CPE]:
    return {
        cpe_single_sign_on,
        CPE(
            "cpe:2.3:a:ibm:security_key_lifecycle_manager:2.6.0.1:*:*:*:*:*:*:*",
            "IBM Security Key Lifecycle Manager 2.6.0.1",
        ),
        CPE(
            "cpe:2.3:a:semperplugins:all_in_one_seo_pack:1.3.6.4:*:*:*:*:wordpress:*:*",
            "Semper Plugins All in One SEO Pack 1.3.6.4 for WordPress",
        ),
        CPE(
            "cpe:2.3:a:tracker-software:pdf-xchange_lite_printer:6.0.320.0:*:*:*:*:*:*:*",
            "Tracker Software PDF-XChange Lite Printer 6.0.320.0",
        ),
    }


@pytest.fixture(scope="module")
def cpe_dset(cpes: set[CPE]) -> CPEDataset:
    return CPEDataset(False, {x.uri: x for x in cpes})


@pytest.fixture(scope="module")
def cves(cpe_single_sign_on) -> set[CVE]:
    return {
        CVE(
            "CVE-2017-1732",
            [cpe_single_sign_on],
            CVE.Impact(5.3, "MEDIUM", 3.9, 1.4),
            "2021-05-26T04:15Z",
            {"CWE-200"},
        ),
        CVE(
            "CVE-2019-4513",
            [cpe_single_sign_on],
            CVE.Impact(8.2, "HIGH", 3.9, 4.2),
            "2000-05-26T04:15Z",
            {"CVE-611"},
        ),
    }


@pytest.fixture(scope="module")
def cve_dset(cves: set[CVE]) -> CVEDataset:
    cve_dset = CVEDataset({x.cve_id: x for x in cves})
    cve_dset.build_lookup_dict(use_nist_mapping=False)
    return cve_dset


@pytest.fixture(scope="module")
def cc_dset(data_dir: Path, cve_dset: CVEDataset, tmp_path_factory) -> CCDataset:
    tmp_dir = tmp_path_factory.mktemp("cc_dset")
    shutil.copytree(data_dir, tmp_dir, dirs_exist_ok=True)

    cc_dset = CCDataset.from_json(tmp_dir / "vulnerable_dataset.json")
    cc_dset.process_protection_profiles()
    cc_dset.extract_data()
    cc_dset.auxillary_datasets.cve_dset = cve_dset
    cc_dset._compute_heuristics()
    return cc_dset


@pytest.fixture
def reference_dataset(data_dir) -> CCDataset:
    return CCDataset.from_json(data_dir / "reference_dataset.json")


@pytest.fixture
def transitive_vulnerability_dataset(data_dir) -> CCDataset:
    return CCDataset.from_json(data_dir / "transitive_vulnerability_dataset.json")


@pytest.fixture
def random_certificate(cc_dset: CCDataset) -> CCCertificate:
    return cc_dset["ebd276cca70fd723"]


def test_match_cpe(cpe_single_sign_on: CPE, random_certificate: CCCertificate):
    assert {cpe_single_sign_on.uri} == random_certificate.heuristics.cpe_matches


def test_find_related_cves(
    cc_dset: CCDataset, cpe_single_sign_on: CPE, cves: set[CVE], random_certificate: CCCertificate
):
    random_certificate.heuristics.cpe_matches = {cpe_single_sign_on.uri}
    cc_dset.compute_related_cves()
    assert {x.cve_id for x in cves} == random_certificate.heuristics.related_cves


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


def test_protection_profile_matching(cc_dset: CCDataset, random_certificate: CCCertificate):
    artificial_pp: ProtectionProfile = ProtectionProfile(
        "Korean National Protection Profile for Single Sign On V1.0",
        "EAL1+",
        pp_link="http://www.commoncriteriaportal.org/files/ppfiles/KECS-PP-0822-2017%20Korean%20National%20PP%20for%20Single%20Sign%20On%20V1.0(eng).pdf",
    )

    random_certificate.protection_profiles = {artificial_pp}

    expected_pp: ProtectionProfile = ProtectionProfile(
        "Korean National Protection Profile for Single Sign On V1.0",
        "EAL1+",
        pp_link="http://www.commoncriteriaportal.org/files/ppfiles/KECS-PP-0822-2017%20Korean%20National%20PP%20for%20Single%20Sign%20On%20V1.0(eng).pdf",
        pp_ids=frozenset(["KECS-PP-0822-2017 SSO V1.0"]),
    )

    cc_dset.process_protection_profiles(to_download=False)
    assert random_certificate.protection_profiles == {expected_pp}


def test_single_record_references_heuristics(random_certificate: CCCertificate):
    # Single record in daset is not affecting nor affected by other records
    assert not random_certificate.heuristics.report_references.directly_referenced_by
    assert not random_certificate.heuristics.report_references.indirectly_referenced_by
    assert not random_certificate.heuristics.report_references.directly_referencing
    assert not random_certificate.heuristics.report_references.indirectly_referencing


def test_reference_dataset(reference_dataset: CCDataset):
    reference_dataset._compute_references()
    test_cert = reference_dataset["692e91451741ef49"]

    assert test_cert.heuristics.report_references.directly_referenced_by == {"BSI-DSZ-CC-0370-2006"}
    assert test_cert.heuristics.report_references.indirectly_referenced_by == {
        "BSI-DSZ-CC-0370-2006",
        "BSI-DSZ-CC-0517-2009",
    }
    assert not test_cert.heuristics.report_references.directly_referencing
    assert not test_cert.heuristics.report_references.indirectly_referencing


def test_direct_transitive_vulnerability_dataset(transitive_vulnerability_dataset: CCDataset):
    transitive_vulnerability_dataset._compute_transitive_vulnerabilities()
    assert transitive_vulnerability_dataset["d0705c9e6fbaeba3"].heuristics.direct_transitive_cves == {"CVE-2013-5385"}


def test_indirect_transitive_vulnerability_dataset(transitive_vulnerability_dataset: CCDataset):
    transitive_vulnerability_dataset._compute_transitive_vulnerabilities()
    assert transitive_vulnerability_dataset["d0705c9e6fbaeba3"].heuristics.indirect_transitive_cves == {"CVE-2013-5385"}


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
