import shutil
import tempfile
from pathlib import Path
from typing import ClassVar, Dict, List
from unittest import TestCase

import tests.data.test_cc_heuristics
from sec_certs.dataset.common_criteria import CCDataset
from sec_certs.dataset.cpe import CPEDataset
from sec_certs.dataset.cve import CVEDataset
from sec_certs.sample.common_criteria import CommonCriteriaCert
from sec_certs.sample.cpe import CPE
from sec_certs.sample.cve import CVE
from sec_certs.sample.protection_profile import ProtectionProfile


class TestCommonCriteriaHeuristics(TestCase):
    dataset_json_path: ClassVar[Path] = Path(tests.data.test_cc_heuristics.__path__[0]) / "vulnerable_dataset.json"  # type: ignore  # mypy issue #1422
    data_dir_path: ClassVar[Path] = dataset_json_path.parent
    tmp_dir: ClassVar[tempfile.TemporaryDirectory]
    cc_dset: CCDataset
    cve_dset: CVEDataset
    cves: List[CVE]
    cpe_dset: CPEDataset
    cpes: List[CPE]

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp_dir = tempfile.TemporaryDirectory()
        shutil.copytree(cls.data_dir_path, cls.tmp_dir.name, dirs_exist_ok=True)

        cls.cc_dset = CCDataset.from_json(Path(cls.tmp_dir.name) / "vulnerable_dataset.json")
        cls.cc_dset.process_protection_profiles()
        cls.cc_dset.download_all_pdfs()
        cls.cc_dset.convert_all_pdfs()
        cls.cc_dset._extract_data()
        cls.cc_dset._compute_heuristics(use_nist_cpe_matching_dict=False)

        cpe_single_sign_on = CPE(
            "cpe:2.3:a:ibm:security_access_manager_for_enterprise_single_sign-on:8.2.2:*:*:*:*:*:*:*",
            "IBM Security Access Manager For Enterprise Single Sign-On 8.2.2",
        )

        cls.cpes = [
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
        ]
        cls.cpe_dset = CPEDataset(True, Path("../"), {x.uri: x for x in cls.cpes})

        cls.cves = [
            CVE(
                "CVE-2017-1732",
                [cpe_single_sign_on],
                CVE.Impact(5.3, "MEDIUM", 3.9, 1.4),
                "2021-05-26T04:15Z",
            ),
            CVE("CVE-2019-4513", [cpe_single_sign_on], CVE.Impact(8.2, "HIGH", 3.9, 4.2), "2000-05-26T04:15Z"),
        ]
        cls.cve_dset = CVEDataset({x.cve_id: x for x in cls.cves})
        cls.cve_dset.build_lookup_dict(use_nist_mapping=False)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp_dir.cleanup()

    def test_load_cpe_dataset(self):
        json_cpe_dset = CPEDataset.from_json(self.data_dir_path / "auxillary_datasets" / "cpe_dataset.json")
        json_cpe_dset.json_path = Path("../")
        self.assertEqual(
            self.cpe_dset, json_cpe_dset, "CPE template dataset does not match CPE dataset loaded from json."
        )

    def test_cpe_lookup_dicts(self):
        self.assertEqual(
            self.cpe_dset.vendors,
            {"ibm", "tracker-software", "semperplugins"},
            "The set of versions in CPE dataset does not match template",
        )
        self.assertEqual(
            self.cpe_dset.vendor_to_versions,
            {"ibm": {"8.2.2", "2.6.0.1"}, "semperplugins": {"1.3.6.4"}, "tracker-software": {"6.0.320.0"}},
            "The CPE lookup dictionary vendor->version of CPE dataset does not match template.",
        )
        self.assertEqual(
            self.cpe_dset.vendor_version_to_cpe,
            {
                ("ibm", "8.2.2"): {
                    CPE(
                        "cpe:2.3:a:ibm:security_access_manager_for_enterprise_single_sign-on:8.2.2:*:*:*:*:*:*:*",
                        "IBM Security Access Manager For Enterprise Single Sign-On 8.2.2",
                    )
                },
                ("ibm", "2.6.0.1"): {
                    CPE(
                        "cpe:2.3:a:ibm:security_key_lifecycle_manager:2.6.0.1:*:*:*:*:*:*:*",
                        "IBM Security Key Lifecycle Manager 2.6.0.1",
                    )
                },
                ("semperplugins", "1.3.6.4"): {
                    CPE(
                        "cpe:2.3:a:semperplugins:all_in_one_seo_pack:1.3.6.4:*:*:*:*:wordpress:*:*",
                        "Semper Plugins All in One SEO Pack 1.3.6.4 for WordPress",
                    )
                },
                ("tracker-software", "6.0.320.0"): {
                    CPE(
                        "cpe:2.3:a:tracker-software:pdf-xchange_lite_printer:6.0.320.0:*:*:*:*:*:*:*",
                        "Tracker Software PDF-XChange Lite Printer 6.0.320.0",
                    )
                },
            },
            "The CPE lookup dictionary (vendor,version)->cpe does not match the template.",
        )

    def test_cve_lookup_dicts(self):
        alt_lookup = {x: set(y) for x, y in self.cve_dset.cpe_to_cve_ids_lookup.items()}
        self.assertEqual(
            alt_lookup,
            {
                "cpe:2.3:a:ibm:security_access_manager_for_enterprise_single_sign-on:8.2.2:*:*:*:*:*:*:*": {
                    x.cve_id for x in self.cves
                }
            },
            "The CVE lookup dicionary cve-> affected cpes does not match the template",
        )

    def test_load_cve_dataset(self):
        json_cve_dset = CVEDataset.from_json(self.data_dir_path / "auxillary_datasets" / "cve_dataset.json")
        self.assertEqual(
            self.cve_dset, json_cve_dset, "CVE template dataset does not match CVE dataset loaded from json."
        )

    def test_match_cpe(self):
        self.assertTrue(
            self.cpes[0].uri in self.cc_dset["ebd276cca70fd723"].heuristics.cpe_matches,
            "The CPE matching algorithm did not find the right CPE.",
        )
        self.assertTrue(
            len(self.cc_dset["ebd276cca70fd723"].heuristics.cpe_matches) == 1, "Exactly one CPE match should be found."
        )

    def test_find_related_cves(self):
        self.cc_dset["ebd276cca70fd723"].heuristics.cpe_matches = [self.cpes[0].uri]
        self.cc_dset.compute_related_cves(use_nist_cpe_matching_dict=False)
        self.assertEqual(
            {x.cve_id for x in self.cves},
            self.cc_dset["ebd276cca70fd723"].heuristics.related_cves,
            "The computed CVEs do not match the excpected CVEs",
        )

    def test_version_extraction(self):
        self.assertEqual(
            self.cc_dset["ebd276cca70fd723"].heuristics.extracted_versions,
            ["8.2"],
            "The version extracted from the sample does not match the template",
        )
        new_cert = CommonCriteriaCert(
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
        self.assertEqual(
            set(new_cert.heuristics.extracted_versions),
            {"5.4", "1.0"},
            "The extracted versions do not match the template.",
        )

    def test_cert_lab_heuristics(self):
        self.assertEqual(self.cc_dset["ebd276cca70fd723"].heuristics.cert_lab, ["BSI"])

    def test_cert_id_heuristics(self):
        self.assertEqual(self.cc_dset["ebd276cca70fd723"].heuristics.cert_id, "BSI-DSZ-CC-0683-2014")

    def test_keywords_heuristics(self):
        extracted_keywords: Dict = self.cc_dset["ebd276cca70fd723"].pdf_data.st_keywords

        self.assertTrue("rules_security_level" in extracted_keywords)
        self.assertEqual(extracted_keywords["rules_security_level"]["EAL3"], 1)

        self.assertTrue("rules_security_assurance_components" in extracted_keywords)
        self.assertEqual(extracted_keywords["rules_security_assurance_components"]["ADV_ARC.1"], 1)
        self.assertEqual(extracted_keywords["rules_security_assurance_components"]["ADV_FSP.3"], 1)
        self.assertEqual(extracted_keywords["rules_security_assurance_components"]["ADV_TDS.2"], 1)

        self.assertTrue("rules_crypto_algs" in extracted_keywords)
        self.assertEqual(extracted_keywords["rules_crypto_algs"]["AES"], 2)

        self.assertTrue("rules_block_cipher_modes" in extracted_keywords)
        self.assertEqual(extracted_keywords["rules_block_cipher_modes"]["CBC"], 2)

    def test_protection_profiles_matching(self):
        artificial_pp: ProtectionProfile = ProtectionProfile(
            "Korean National Protection Profile for Single Sign On V1.0",
            "http://www.commoncriteriaportal.org/files/ppfiles/KECS-PP-0822-2017%20Korean%20National%20PP%20for%20Single%20Sign%20On%20V1.0(eng).pdf",
        )
        self.cc_dset["ebd276cca70fd723"].protection_profiles = {artificial_pp}
        expected_pp: ProtectionProfile = ProtectionProfile(
            "Korean National Protection Profile for Single Sign On V1.0",
            "http://www.commoncriteriaportal.org/files/ppfiles/KECS-PP-0822-2017%20Korean%20National%20PP%20for%20Single%20Sign%20On%20V1.0(eng).pdf",
            frozenset(["KECS-PP-0822-2017 SSO V1.0"]),
        )
        self.cc_dset.process_protection_profiles(to_download=False)
        self.assertSetEqual(self.cc_dset["ebd276cca70fd723"].protection_profiles, {expected_pp})

    def test_single_record_dependency_heuristics(self):
        # Single record in daset is not affecting nor affected by other records
        heuristics = self.cc_dset["ebd276cca70fd723"].heuristics
        self.assertEqual(heuristics.directly_affected_by, None)
        self.assertEqual(heuristics.indirectly_affected_by, None)
        self.assertEqual(heuristics.directly_affecting, None)
        self.assertEqual(heuristics.indirectly_affecting, None)

    def test_dependency_dataset(self):
        dependency_dataset = CCDataset.from_json(self.data_dir_path / "dependency_dataset.json")
        dependency_dataset._compute_dependencies()
        test_cert = dependency_dataset["692e91451741ef49"]

        self.assertEqual(test_cert.heuristics.directly_affected_by, ["BSI-DSZ-CC-0370-2006"])
        self.assertEqual(test_cert.heuristics.indirectly_affected_by, {"BSI-DSZ-CC-0370-2006", "BSI-DSZ-CC-0517-2009"})
        self.assertEqual(test_cert.heuristics.directly_affecting, {"BSI-DSZ-CC-0268-2005"})
        self.assertEqual(test_cert.heuristics.indirectly_affecting, {"BSI-DSZ-CC-0268-2005"})
